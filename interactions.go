package interactions

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"sync"
	"time"

	"github.com/awslabs/aws-lambda-go-api-proxy/handlerfunc"
	"github.com/rs/zerolog/log"

	"github.com/Postcord/objects"
	"github.com/Postcord/rest"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const tracerName = "postcord"

type (
	HandlerFunc func(context.Context, *objects.Interaction) *objects.InteractionResponse
)

func makeDefaultHandler(component string) HandlerFunc {
	return func(ctx context.Context, interaction *objects.Interaction) *objects.InteractionResponse {
		_, span := otel.Tracer(tracerName).Start(ctx, "interactions.defaultHandler")
		defer span.End()
		span.SetAttributes(attribute.String("component", component))
		err := fmt.Errorf("no handler for %s", component)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		zerolog.Ctx(ctx).Error().Err(err).Msg("")

		return &objects.InteractionResponse{
			Type: objects.ResponseChannelMessageWithSource,
			Data: &objects.InteractionApplicationCommandCallbackData{
				Content: fmt.Sprintf("Please let the developer of this bot know they have not yet set a handler for the %s interaction type.", component),
				Flags:   objects.MsgFlagEphemeral,
			},
		}
	}
}

// App is the primary interactions server
type App struct {
	extraProps          map[string]interface{}
	propsLock           sync.RWMutex
	logger              zerolog.Logger
	restClient          *rest.Client
	commandHandler      HandlerFunc
	componentHandler    HandlerFunc
	autocompleteHandler HandlerFunc
	modalHandler        HandlerFunc
	pubKey              ed25519.PublicKey
}

// Create a new interactions server instance
func New(config *Config) (*App, error) {
	pubKey, err := parsePublicKey(config.PublicKey)
	if err != nil {
		return nil, err
	}

	a := &App{
		extraProps: make(map[string]interface{}),
		pubKey:     pubKey,
	}

	if config.Logger == nil {
		a.logger = log.Logger
	} else {
		a.logger = *config.Logger
	}

	var restClient *rest.Client
	if config.RESTClient == nil {
		restClient = rest.New(&rest.Config{
			UserAgent:     "PostcordRest/1.0 (Linux) Postcord (https://github.com/Postcord)",
			Authorization: config.Token,
			Ratelimiter: rest.NewMemoryRatelimiter(&rest.MemoryConf{
				MaxRetries: 3,
			}),
		})
	} else {
		restClient = config.RESTClient
	}

	a.restClient = restClient

	a.commandHandler = makeDefaultHandler("command")
	a.componentHandler = makeDefaultHandler("component")
	a.autocompleteHandler = makeDefaultHandler("autocomplete")
	a.modalHandler = makeDefaultHandler("modal")

	return a, nil
}

// CommandHandler sets the function to handle slash command events
func (a *App) CommandHandler(handler HandlerFunc) {
	a.commandHandler = handler
}

// ComponentHandler sets the function to handle Component events.
func (a *App) ComponentHandler(handler HandlerFunc) {
	a.componentHandler = handler
}

func (a *App) AutocompleteHandler(handler HandlerFunc) {
	a.autocompleteHandler = handler
}

func (a *App) ModalHandler(handler HandlerFunc) {
	a.modalHandler = handler
}

// FastHTTPHandler exposes a fasthttp handler to process incoming interactions
func (a *App) FastHTTPHandler() fasthttp.RequestHandler {
	return fasthttpadaptor.NewFastHTTPHandler(a.HTTPHandler())
}

// LambdaHandler exposes an AWS APi Gateway Lambda handler to process incoming interactions
func (a *App) LambdaHandler() LambdaHandler {
	return handlerfunc.New(a.HTTPHandler()).ProxyWithContext
}

// ServeHTTP makes App implement the http.Handler interface
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.HTTPHandler()(w, r)
}

func FailUnknownError(w http.ResponseWriter, jr *json.Encoder) {
	w.Header().Set("Content-Type", "application/json")
	_ = jr.Encode(objects.InteractionResponse{
		Type: objects.ResponseChannelMessageWithSource,
		Data: &objects.InteractionApplicationCommandCallbackData{
			Content: "An unknown error occurred",
			Flags:   objects.MsgFlagEphemeral,
		},
	})
}

// HTTPHandler exposes a net/http handler to process incoming interactions
func (a *App) HTTPHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newCtx, span := otel.Tracer(tracerName).Start(r.Context(), "interactions.HTTPHandler")
		defer span.End()

		jr := json.NewEncoder(w)
		signature := r.Header.Get("X-Signature-Ed25519")
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			FailUnknownError(w, jr)
			return
		}
		body := append([]byte(r.Header.Get("X-Signature-Timestamp")), bodyBytes...)
		if !verifyMessage(body, signature, a.pubKey) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		resp, err := a.ProcessRequest(a.logger.WithContext(newCtx), bodyBytes)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			FailUnknownError(w, jr)
			return
		}

		if (resp.Type == objects.ResponseChannelMessageWithSource ||
			resp.Type == objects.ResponseUpdateMessage) && len(resp.Data.Files) > 0 {
			m := multipart.NewWriter(w)
			w.Header().Set("Content-Type", m.FormDataContentType())
			for n, file := range resp.Data.Files {
				// Generate the attachment object, assign a number to it, and write it to the multipart writer
				attach, err := file.GenerateAttachment(objects.Snowflake(n+1), m)
				if err != nil {
					a.logger.Error().Err(err).Msg("failed to generate attachment")
					continue
				}
				resp.Data.Attachments = append(resp.Data.Attachments, attach)
			}

			if field, err := m.CreateFormField("payload_json"); err != nil {
				a.logger.Error().Err(err).Msg("failed to create payload_json form field")
				FailUnknownError(w, jr)
				return
			} else {
				if err := json.NewEncoder(field).Encode(resp); err != nil {
					a.logger.Error().Err(err).Msg("failed to encode payload_json")
					FailUnknownError(w, jr)
					return
				}
			}
			if err := m.Close(); err != nil {
				a.logger.Error().Err(err).Msg("failed to close multipart writer")
				FailUnknownError(w, jr)
				return
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err = jr.Encode(resp)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to write response")
		}
	})
}

// ProcessRequest is used internally to process a validated request.
// It is exposed to allow users to tied Postcord in with any web framework
// of their choosing.  Ensure you only pass validated requests.
func (a *App) ProcessRequest(ctx context.Context, data []byte) (resp *objects.InteractionResponse, err error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "interactions.ProcessRequest")
	defer span.End()

	var req objects.Interaction
	err = json.Unmarshal(data, &req)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to unmarshal request")
		err = fmt.Errorf("failed to decode request body")
		return
	}

	span.SetAttributes(attribute.Int("interaction_type", int(req.Type)), attribute.String("interaction_id", req.ID.String()))

	l := zerolog.Ctx(ctx)
	newLogger := l.With().Int("interaction_type", int(req.Type)).Int("interaction_id", int(req.ID)).Logger()
	ctx = newLogger.WithContext(ctx)

	l.Debug().Msg("received request")

	// Discord requires all interactions respond within 5 seconds
	// so we may as well enforce this here
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(5*time.Second))
	defer cancel()

	switch req.Type {
	case objects.InteractionRequestPing:
		resp = &objects.InteractionResponse{Type: objects.ResponsePong}
		return
	case objects.InteractionApplicationCommand:
		resp = a.commandHandler(ctx, &req)
	case objects.InteractionComponent:
		resp = a.componentHandler(ctx, &req)
		if resp == nil {
			return &objects.InteractionResponse{
				Type: objects.ResponseDeferredMessageUpdate,
			}, nil
		}
	case objects.InteractionAutoComplete:
		resp = a.autocompleteHandler(ctx, &req)
	case objects.InteractionModalSubmit:
		resp = a.modalHandler(ctx, &req)
	default:
		err = fmt.Errorf("unknown interaction type: %d", req.Type)
		return
	}

	if resp == nil {
		err = fmt.Errorf("nil response")
	} else {
		l.Debug().Msg("sending response")
	}

	return
}

// Get retrieves a value from the global context
func (a *App) Get(key string) (interface{}, bool) {
	a.propsLock.RLock()
	defer a.propsLock.RUnlock()
	obj, ok := a.extraProps[key]
	return obj, ok
}

// Set stores a value in the global context.  This is suitable for things like database connections.
func (a *App) Set(key string, obj interface{}) {
	a.propsLock.Lock()
	defer a.propsLock.Unlock()
	a.extraProps[key] = obj
}

// Rest exposes the internal Rest client so you can make calls to the Discord API
func (a *App) Rest() *rest.Client {
	return a.restClient
}

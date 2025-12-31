package otel

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Provider manages the OpenTelemetry SDK lifecycle.
// Call Shutdown when done to flush pending telemetry data.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	loggerProvider *sdklog.LoggerProvider
	shutdownFuncs  []func(context.Context) error
	enabled        bool
}

var (
	globalProvider *Provider
	providerMu     sync.RWMutex
)

// Init initializes the OpenTelemetry SDK based on configuration.
// Returns a Provider that must be shut down via Shutdown().
// If OTel is disabled or not configured, returns a no-op provider.
//
// This function is safe to call multiple times; subsequent calls
// after the first return the existing provider.
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	providerMu.Lock()
	defer providerMu.Unlock()

	if globalProvider != nil {
		return globalProvider, nil
	}

	// Check environment override
	if envEnabled := os.Getenv("DEPUTY_OTEL_ENABLED"); envEnabled != "" {
		cfg.Enabled = strings.EqualFold(envEnabled, "true") || envEnabled == "1"
	}

	if !cfg.Enabled {
		globalProvider = &Provider{enabled: false}
		return globalProvider, nil
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &Provider{enabled: true}

	// Build resource with service info
	res, err := buildResource(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Initialize tracer provider
	if cfg.Traces.Enabled {
		tp, shutdownTrace, err := initTracerProvider(ctx, cfg, res)
		if err != nil {
			slog.Warn("failed to initialize tracer provider", "error", err)
		} else {
			p.tracerProvider = tp
			p.shutdownFuncs = append(p.shutdownFuncs, shutdownTrace)
			otel.SetTracerProvider(tp)
		}
	}

	// Initialize meter provider
	if cfg.Metrics.Enabled {
		mp, shutdownMeter, err := initMeterProvider(ctx, cfg, res)
		if err != nil {
			slog.Warn("failed to initialize meter provider", "error", err)
		} else {
			p.meterProvider = mp
			p.shutdownFuncs = append(p.shutdownFuncs, shutdownMeter)
			otel.SetMeterProvider(mp)
		}
	}

	// Initialize logger provider
	if cfg.Logs.Enabled {
		lp, shutdownLogger, err := initLoggerProvider(ctx, cfg, res)
		if err != nil {
			slog.Warn("failed to initialize logger provider", "error", err)
		} else {
			p.loggerProvider = lp
			p.shutdownFuncs = append(p.shutdownFuncs, shutdownLogger)
			global.SetLoggerProvider(lp)
		}
	}

	// Set up propagation
	otel.SetTextMapPropagator(buildPropagator(cfg.Traces.Propagators))

	// Set global error handler - log at Warn so operators notice telemetry issues
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		slog.Warn("otel error", "error", err)
	}))

	globalProvider = p
	return p, nil
}

// Shutdown gracefully shuts down all providers, flushing pending data.
// Safe to call multiple times; subsequent calls are no-ops.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || !p.enabled {
		return nil
	}

	var errs []error
	for _, fn := range p.shutdownFuncs {
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	p.shutdownFuncs = nil

	return errors.Join(errs...)
}

// Enabled reports whether OTel instrumentation is active.
func (p *Provider) Enabled() bool {
	return p != nil && p.enabled
}

// Tracer returns a named tracer for creating spans.
// Returns a no-op tracer if OTel is disabled.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// Meter returns a named meter for recording metrics.
// Returns a no-op meter if OTel is disabled.
func Meter(name string) metric.Meter {
	return otel.Meter(name)
}

// IsEnabled reports whether the global provider is enabled.
func IsEnabled() bool {
	providerMu.RLock()
	defer providerMu.RUnlock()
	return globalProvider != nil && globalProvider.enabled
}

// LoggerProvider returns the logger provider, or nil if not initialized.
func (p *Provider) LoggerProvider() *sdklog.LoggerProvider {
	if p == nil {
		return nil
	}
	return p.loggerProvider
}

// buildResource creates an OTel resource with service information.
func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	version := cfg.ServiceVersion
	if version == "" {
		version = "unknown"
	}

	return resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(version),
		),
		resource.WithProcessRuntimeDescription(),
		resource.WithHost(),
	)
}

// initTracerProvider sets up the tracer provider with OTLP exporter.
func initTracerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	var client otlptrace.Client
	var err error

	ctx, cancel := context.WithTimeout(ctx, cfg.Exporter.Timeout)
	defer cancel()

	switch cfg.Exporter.Protocol {
	case "http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Exporter.Endpoint),
			otlptracehttp.WithTimeout(cfg.Exporter.Timeout),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Exporter.Headers))
		}
		client = otlptracehttp.NewClient(opts...)

	default: // grpc
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Exporter.Endpoint),
			otlptracegrpc.WithTimeout(cfg.Exporter.Timeout),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Exporter.Headers))
		}
		client = otlptracegrpc.NewClient(opts...)
	}

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, nil, err
	}

	// Build sampler
	var sampler sdktrace.Sampler
	if cfg.Traces.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.Traces.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(cfg.Traces.SampleRate),
		)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx)
	}

	return tp, shutdown, nil
}

// initMeterProvider sets up the meter provider with OTLP exporter.
func initMeterProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdkmetric.MeterProvider, func(context.Context) error, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Exporter.Timeout)
	defer cancel()

	var exporter sdkmetric.Exporter
	var err error

	switch cfg.Exporter.Protocol {
	case "http":
		opts := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(cfg.Exporter.Endpoint),
			otlpmetrichttp.WithTimeout(cfg.Exporter.Timeout),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Exporter.Headers))
		}
		exporter, err = otlpmetrichttp.New(ctx, opts...)

	default: // grpc
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(cfg.Exporter.Endpoint),
			otlpmetricgrpc.WithTimeout(cfg.Exporter.Timeout),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlpmetricgrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Exporter.Headers))
		}
		exporter, err = otlpmetricgrpc.New(ctx, opts...)
	}

	if err != nil {
		return nil, nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exporter,
				sdkmetric.WithInterval(cfg.Metrics.Interval),
			),
		),
	)

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return mp.Shutdown(ctx)
	}

	return mp, shutdown, nil
}

// initLoggerProvider sets up the logger provider with OTLP exporter.
func initLoggerProvider(ctx context.Context, cfg Config, res *resource.Resource) (*sdklog.LoggerProvider, func(context.Context) error, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Exporter.Timeout)
	defer cancel()

	var exporter sdklog.Exporter
	var err error

	switch cfg.Exporter.Protocol {
	case "http":
		opts := []otlploghttp.Option{
			otlploghttp.WithEndpoint(cfg.Exporter.Endpoint),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(cfg.Exporter.Headers))
		}
		exporter, err = otlploghttp.New(ctx, opts...)

	default: // grpc
		opts := []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(cfg.Exporter.Endpoint),
		}
		if cfg.Exporter.Insecure {
			opts = append(opts, otlploggrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		}
		if len(cfg.Exporter.Headers) > 0 {
			opts = append(opts, otlploggrpc.WithHeaders(cfg.Exporter.Headers))
		}
		exporter, err = otlploggrpc.New(ctx, opts...)
	}

	if err != nil {
		return nil, nil, err
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return lp.Shutdown(ctx)
	}

	return lp, shutdown, nil
}

// buildPropagator creates a composite propagator from the configured formats.
func buildPropagator(formats []string) propagation.TextMapPropagator {
	if len(formats) == 0 {
		formats = []string{"tracecontext", "baggage"}
	}

	var propagators []propagation.TextMapPropagator
	for _, f := range formats {
		switch strings.ToLower(f) {
		case "tracecontext":
			propagators = append(propagators, propagation.TraceContext{})
		case "baggage":
			propagators = append(propagators, propagation.Baggage{})
		}
	}

	if len(propagators) == 0 {
		return propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		)
	}

	return propagation.NewCompositeTextMapPropagator(propagators...)
}

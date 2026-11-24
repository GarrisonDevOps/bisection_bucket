# frozen_string_literal: true

module RedisCloudAuth
  # Process-global registry of providers, keyed by a marshallable descriptor
  # (a Hash of simple values). Providers are memoized so every pooled
  # connection and thread shares one provider, which caches the access token
  # and refreshes it as needed.
  #
  # The indirection through a descriptor is deliberate: the descriptor (not the
  # live provider) is embedded in the Redis config, so the config stays
  # marshallable when Sidekiq round-trips it through Marshal.dump/load. The
  # provider itself (holds tokens, does I/O) is resolved here at runtime and
  # never serialized.
  #
  # Built-in providers: +:azure+ (Microsoft Entra, via the az-identity gem),
  # +:elasticache+ (Amazon ElastiCache IAM, via aws-sigv4), and +:gcp+ (Google
  # Memorystore IAM, via googleauth). Register more with {register_provider}.
  module Registry
    MUTEX = Mutex.new

    @providers = {}   # descriptor => live provider
    @builders  = {}   # provider name (Symbol) => ->(descriptor) { provider }

    class << self
      # Returns the memoized provider for +descriptor+, building it on first
      # use. The middleware calls this on every command on a token-authed
      # connection, so the cache-hit path is lock-free; only the first build
      # per descriptor takes the mutex.
      def fetch(descriptor)
        @providers[descriptor] || MUTEX.synchronize { @providers[descriptor] ||= build(descriptor) }
      end

      # Register a builder for a provider name. The block receives the
      # descriptor Hash and must return an object responding to #call
      # (=> [username, password]) and #expires_at (=> Time or nil).
      def register_provider(name, &builder)
        MUTEX.synchronize { @builders[name.to_sym] = builder }
      end

      # Inject a prebuilt provider for a descriptor. Intended for tests.
      def store(descriptor, provider)
        MUTEX.synchronize { @providers[descriptor] = provider }
      end

      def clear!
        MUTEX.synchronize { @providers = {} }
      end

      private

      def build(descriptor)
        name = descriptor[:provider].to_s.to_sym
        builder = @builders[name] || default_builder(name)
        raise Error, "unknown Redis credentials provider: #{descriptor[:provider].inspect}" unless builder

        builder.call(descriptor)
      end

      # Built-in providers are required lazily so their (optional) backing gems
      # are only loaded when actually used.
      def default_builder(name)
        case name
        when :azure
          lambda do |descriptor|
            require_relative "providers/azure"
            Providers::Azure.build(descriptor)
          end
        when :elasticache
          lambda do |descriptor|
            require_relative "providers/elasticache"
            Providers::ElastiCache.build(descriptor)
          end
        when :gcp
          lambda do |descriptor|
            require_relative "providers/gcp"
            Providers::GCP.build(descriptor)
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Utils
    module StrongMemoize
      ExpiringEntry = Struct.new(:value, :expires_at)
      private_constant :ExpiringEntry

      # Instead of writing patterns like this:
      #
      #     def trigger_from_token
      #       return @trigger if defined?(@trigger)
      #
      #       @trigger = Ci::Trigger.find_by_token(params[:token].to_s)
      #     end
      #
      # We could write it like:
      #
      #     include Gitlab::Utils::StrongMemoize
      #
      #     def trigger_from_token
      #       Ci::Trigger.find_by_token(params[:token].to_s)
      #     end
      #     strong_memoize_attr :trigger_from_token
      #
      #     def enabled?
      #       Feature.enabled?(:some_feature)
      #     end
      #     strong_memoize_attr :enabled?
      #
      def strong_memoize(name)
        key = ivar(name)

        if instance_variable_defined?(key)
          instance_variable_get(key)
        else
          instance_variable_set(key, yield)
        end
      end

      # Works the same way as "strong_memoize" but takes
      # a second argument - expire_in. This allows invalidate
      # the data after specified number of seconds.
      #
      # The memo lives in `@<name>` as one frozen entry of value and expiry, so
      # a reader sees a whole entry or none. A refresh already running when
      # `clear_memoization` is called still stores its value until it expires.
      def strong_memoize_with_expiration(name, expire_in)
        key = ivar(name)

        entry = instance_variable_get(key)
        return entry.value if entry.is_a?(ExpiringEntry) && entry.expires_at.future?

        value = yield
        instance_variable_set(key, ExpiringEntry.new(value, Time.current + expire_in).freeze)
        value
      end

      def strong_memoize_with(name, *args)
        container = strong_memoize(name) { {} }

        if container.key?(args)
          container[args]
        else
          container[args] = yield
        end
      end

      def strong_memoized?(name)
        key = ivar(StrongMemoize.normalize_key(name))
        instance_variable_defined?(key)
      end

      def clear_memoization(name)
        remove_memoized_ivar(ivar(StrongMemoize.normalize_key(name)))
      end

      module StrongMemoizeClassMethods
        def strong_memoize_attr(method_name)
          member_name = StrongMemoize.normalize_key(method_name)

          StrongMemoize.send(:do_strong_memoize, self, method_name, member_name) # rubocop:disable GitlabSecurity/PublicSend
        end
      end

      def self.included(base)
        base.singleton_class.prepend(StrongMemoizeClassMethods)
      end

      private

      def remove_memoized_ivar(key)
        return unless instance_variable_defined?(key)

        begin
          remove_instance_variable(key)
        rescue NameError
          # Another thread removed it between the check and the removal.
        end
      end

      # Convert `"name"`/`:name` into `:@name`
      #
      # Depending on a type ensure that there's a single memory allocation
      def ivar(name)
        case name
        when Symbol, String
          :"@#{name}"
        else
          raise ArgumentError, "Invalid type of '#{name}'"
        end
      end

      class << self
        def normalize_key(key)
          return key unless key.end_with?('!', '?')

          # Replace invalid chars like `!` and `?` with allowed Unicode codeparts.
          key.to_s.tr('!?', "\uFF01\uFF1F")
        end

        private

        def do_strong_memoize(klass, method_name, member_name)
          method = klass.instance_method(method_name)

          unless method.arity == 0
            raise <<~ERROR
              Using `strong_memoize_attr` on methods with parameters is not supported.

              Use `strong_memoize_with` instead.
              See https://docs.gitlab.com/ee/development/utilities.html#strongmemoize
            ERROR
          end

          # Methods defined within a class method are already public by default, so we don't need to
          # explicitly make them public.
          scope = %i[private protected].find do |scope|
            klass.send("#{scope}_instance_methods") # rubocop:disable GitlabSecurity/PublicSend
              .include? method_name
          end

          klass.define_method(method_name) do |&block|
            strong_memoize(member_name) do
              method.bind_call(self, &block)
            end
          end

          klass.send(scope, method_name) if scope # rubocop:disable GitlabSecurity/PublicSend
        end
      end
    end
  end
end

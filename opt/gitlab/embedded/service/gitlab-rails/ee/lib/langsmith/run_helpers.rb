# frozen_string_literal: true

module Langsmith
  module RunHelpers
    module RunHelpersClassMethods
      # Trace the specified method with Langsmith.
      #
      # Args:
      #   method_name: Name of the method to trace
      #   name: Human readable name of the process of the method
      #   run_type: Type of the process. One of "tool", "chain", "llm", "retriever", "embedding", "prompt", "parser".
      #   tags: Tags of the process.
      #   class_method: Pass `true` if the method is a class method.
      #
      # Example:
      #
      #   ```ruby
      #   def do_somthing
      #     ...
      #   end
      #   traceable :do_somthing
      #   ```
      def traceable(
        method_name,
        name: nil,
        run_type: 'chain',
        tags: %i[duo_chat],
        class_method: false
      )
        return unless RunHelpers.enabled?

        RunHelpers.send(:do_trace, self, method_name, name, run_type, tags, class_method) # rubocop:disable GitlabSecurity/PublicSend -- This is safe.
      end
    end

    def trace(klass_name, method_name, name, run_type, tags, *args, **kwargs)
      correlation_id = Labkit::Correlation::CorrelationId.current_or_new_id

      Langsmith::RunHelpers.run_tree ||= {}
      Langsmith::RunHelpers.run_tree[correlation_id] ||= []

      parent_id = Langsmith::RunHelpers.run_tree[correlation_id][-1]
      run_id = SecureRandom.uuid
      error_message = ""

      name ||= "#{klass_name}##{method_name}"

      langsmith_client.post_run(
        run_id: run_id,
        name: name,
        run_type: run_type,
        inputs: run_inputs(method_name, args, kwargs),
        parent_id: parent_id,
        extra: run_extra(correlation_id),
        tags: tags
      )

      Langsmith::RunHelpers.run_tree[correlation_id].push(run_id)

      result = yield
    rescue => e # rubocop:disable Style/RescueStandardError -- Any errors need to be captured in tracing.
      error_message = "#{e.class} #{e.message} \n #{e.backtrace}"
      raise e
    ensure
      Langsmith::RunHelpers.run_tree[correlation_id].pop

      langsmith_client.patch_run(
        run_id: run_id,
        outputs: run_outputs(result),
        error: error_message
      )
    end

    def self.enabled?
      Gitlab.dev_or_test_env? && Langsmith::Client.enabled?
    end

    # Generate the distributed tracing LangSmith header.
    # See https://docs.gitlab.com/ee/development/ai_features/duo_chat.html#tracing-with-langsmith
    # and https://docs.smith.langchain.com/how_to_guides/tracing/distributed_tracing
    def self.to_headers
      return {} unless Langsmith::RunHelpers.run_tree

      correlation_id = Labkit::Correlation::CorrelationId.current_or_new_id
      current_run_tree = Langsmith::RunHelpers.run_tree[correlation_id]

      return {} unless current_run_tree

      current_time = Time.current.strftime('%Y%m%dT%H%M%SZ')
      {
        'langsmith-trace' => "#{current_time}#{current_run_tree[-1]}"
      }
    end

    def self.included(base)
      base.singleton_class.prepend(RunHelpersClassMethods)
    end

    def self.extended(base)
      base.class_eval do
        extend Langsmith::RunHelpers::RunHelpersClassMethods
      end
    end

    private

    def run_inputs(method_name, args, kwargs)
      {
        'self' => {
          'instance' => to_s,
          'variables' => instance_values.inspect
        },
        'method' => {
          'name' => method_name,
          'args' => args.inspect,
          'kwargs' => kwargs.inspect
        }
      }
    end

    def run_extra(correlation_id)
      {
        'metadata' => {
          'correlation_id' => correlation_id
        }
      }
    end

    def run_outputs(result)
      {
        'result' => result.inspect
      }
    end

    def langsmith_client
      @langsmith_client ||= Langsmith::Client.new
    end

    class << self
      attr_accessor :run_tree

      private

      def do_trace(klass, method_name, name, run_type, tags, class_method)
        if class_method
          method = klass.send(:method, method_name) # rubocop:disable GitlabSecurity/PublicSend -- This is safe.

          klass.define_singleton_method(method_name) do |*args, **kwargs, &block|
            trace(self.name, method_name, name, run_type, tags, *args, **kwargs) do
              method.call(*args, **kwargs, &block)
            end
          end
        else
          method = klass.instance_method(method_name)

          klass.define_method(method_name) do |*args, **kwargs, &block|
            trace(self.class.name, method_name, name, run_type, tags, *args, **kwargs) do
              method.bind_call(self, *args, **kwargs, &block)
            end
          end
        end
      end
    end
  end
end

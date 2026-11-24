# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module Completions
        class CategorizeQuestion < Base
          extend ::Gitlab::Utils::Override
          include Gitlab::Utils::StrongMemoize

          SCHEMA_URL = 'iglu:com.gitlab/ai_question_category/jsonschema/1-2-0'

          private_class_method def self.load_xml(filename)
            File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', filename)).tr("\n", '')
          end

          CATEGORY_KEY = 'category'
          DETAILED_CATEGORY_KEY = 'detailed_category'
          LANGUAGE_KEY = 'language'

          LLM_MATCHING_CATEGORIES_XML = load_xml('categories.xml') # mandatory category definition
          LLM_MATCHING_LABELS_XML = load_xml('labels.xml') # boolean attribute definitions

          # rubocop:disable CodeReuse/ActiveRecord -- Array#pluck
          LLM_MATCHING_CATEGORIES = Hash.from_xml(LLM_MATCHING_CATEGORIES_XML)
                                        .dig('root', 'row').pluck(CATEGORY_KEY)
          LLM_MATCHING_DETAILED_CATEGORIES = Hash.from_xml(LLM_MATCHING_CATEGORIES_XML)
                                                 .dig('root', 'row').pluck(DETAILED_CATEGORY_KEY)
          LLM_MATCHING_LABELS = Hash.from_xml(LLM_MATCHING_LABELS_XML)
                                    .dig('root', 'label').pluck('type')
          # rubocop:enable CodeReuse/ActiveRecord -- Array#pluck

          LANGUAGE_CODES = I18nData.languages.keys.map!(&:downcase)

          REQUIRED_KEYS = [CATEGORY_KEY, DETAILED_CATEGORY_KEY].freeze
          OPTIONAL_KEYS = [LANGUAGE_KEY, *LLM_MATCHING_LABELS].freeze
          PERMITTED_KEYS = REQUIRED_KEYS + OPTIONAL_KEYS

          # Some models (for example Claude Sonnet 4.5) fence the JSON despite the prompt.
          # Anchored to the whole response so prose around a JSON block is still rejected.
          JSON_CODE_FENCE = /\A\s*```[^\n]*\n(.*)```\s*\z/m

          override :inputs
          def inputs
            previous_message = messages[-2]
            previous_answer = previous_message&.assistant? ? previous_message.content : nil

            {
              question: options[:question],
              previous_answer: previous_answer
            }
          end

          override :root_namespace
          def root_namespace
            Namespace.find_by_id(options[:root_namespace_id])
          end
          strong_memoize_attr :root_namespace

          private

          override :post_process
          def post_process(response)
            return response if response.is_a?(Hash) && response['detail'].is_a?(String)

            unless response.is_a?(String)
              return default_error("Expected response content to be a String, got #{response.class} instead")
            end

            begin
              parsed = ::Gitlab::Json::SafeParser.parse(response[JSON_CODE_FENCE, 1] || response)
            rescue JSON::ParserError
              return default_error('Response was not valid JSON')
            end

            unless parsed.is_a?(Hash)
              return default_error("Expected response content to be a Hash, got #{parsed.class} instead")
            end

            track(attributes(parsed)) ? '' : { 'detail' => 'Event not tracked' }
          end

          def default_error(message)
            log_error(message: message, event_name: 'error', ai_component: 'duo_chat')

            { 'detail' => DEFAULT_ERROR }
          end

          def attributes(response)
            # Turn array of matched label strings into boolean attributes
            labels = response.delete('labels')
            if labels.is_a?(Array)
              labels.each do |label|
                response[label] = true if LLM_MATCHING_LABELS.include?(label)
              end
            end

            data = response.slice(*PERMITTED_KEYS)

            check!(data, CATEGORY_KEY, LLM_MATCHING_CATEGORIES)
            check!(data, DETAILED_CATEGORY_KEY, LLM_MATCHING_DETAILED_CATEGORIES)
            check!(data, LANGUAGE_KEY, LANGUAGE_CODES)

            data.merge(Gitlab::Llm::ChatMessageAnalyzer.new(messages).execute)
          end

          def valid?
            messages.present?
          rescue ActiveRecord::RecordNotFound
            false
          end

          def messages
            message = ::Ai::Conversation::Message.find_for_user!(options[:message_id], user)
            ::Gitlab::Llm::ChatStorage.new(user, message.thread).messages_up_to(options[:message_id])
          end
          strong_memoize_attr :messages

          def track(attributes)
            return false if attributes.empty?

            unless contains_categories?(attributes)
              error_message = 'Response did not contain defined categories'
              log_error(message: error_message,
                event_name: 'error',
                ai_component: 'duo_chat')
              return false
            end

            context = SnowplowTracker::SelfDescribingJson.new(SCHEMA_URL, attributes)

            Gitlab::Tracking.event(
              self.class.to_s,
              "ai_question_category",
              context: [context],
              requestId: tracking_context[:request_id],
              user: user
            )
          end

          def contains_categories?(hash)
            REQUIRED_KEYS.each { |key| return false unless hash.has_key?(key) }
          end

          def check!(data, key, list)
            return unless data[key]

            return if list.include?(data[key])

            data[key] = '[Invalid]'
          end

          override :unit_primitive_name
          def unit_primitive_name
            # The permissions to use "categorize question" are not different from the ones for duo chat,
            # so we decided not to use the more specific Unit Primitive here
            # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203115#note_2725395334
            :duo_classic_chat
          end
        end
      end
    end
  end
end

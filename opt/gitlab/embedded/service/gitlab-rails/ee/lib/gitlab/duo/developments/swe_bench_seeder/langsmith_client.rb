# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class LangsmithClient
          def self.save_issue_urls_to_langsmith(issue_data, dataset_name)
            langchain_api_key = Config.langsmith_api_key!(
              missing_message: "Warning: Missing LANGCHAIN_API_KEY. Cannot save issue URLs to LangSmith."
            )
            return unless langchain_api_key

            puts "\nSaving #{issue_data.size} issue URLs to LangSmith dataset: #{dataset_name}"

            # Delete existing dataset if it exists, then create a new one
            dataset_id = delete_and_create_dataset(langchain_api_key, dataset_name)
            return unless dataset_id

            # Add examples to the dataset
            add_examples_to_dataset(langchain_api_key, dataset_id, issue_data)

            puts "Successfully saved #{issue_data.size} issue URLs to LangSmith dataset: #{dataset_name}"
          rescue StandardError => e
            puts "Error saving issue URLs to LangSmith: #{e.message}"
            puts e.backtrace.first(5).join("\n")
          end

          def self.delete_and_create_dataset(api_key, dataset_name)
            # Try to find and delete existing dataset first
            existing_dataset_id = find_dataset(api_key, dataset_name)
            if existing_dataset_id
              puts <<~MESSAGE
                WARNING: Found existing dataset: #{dataset_name} (ID: #{existing_dataset_id}).

                Please first delete the dataset manually via LangSmith and rerun the seeder:
                https://smith.langchain.com/o/477de7ad-583e-47b6-a1c4-c4a0300e7aca/datasets/#{existing_dataset_id}

                All experiments linked to the previous dataset will be lost.
              MESSAGE
              raise "Dataset '#{dataset_name}' already exists (ID: #{existing_dataset_id}). " \
                "Delete it manually at: " \
                "https://smith.langchain.com/o/477de7ad-583e-47b6-a1c4-c4a0300e7aca/datasets/#{existing_dataset_id}"
            end

            # Create new dataset (using 'name' field as per API requirements)
            response = Config.langsmith_request(
              method: :post,
              path: '/api/v1/datasets',
              body: {
                name: dataset_name,
                description: "Issue URLs created by SWE Bench seeder"
              },
              api_key: api_key
            )

            unless response.success?
              puts "Failed to create dataset: #{response.code} #{response.message}"
              puts "Response body: #{response.body}"
              return
            end

            dataset_data = ::Gitlab::Json.safe_parse(response.body)
            dataset_id = dataset_data['id'] || dataset_data['dataset_id']
            puts "Created new dataset: #{dataset_name} (ID: #{dataset_id})"
            dataset_id
          end

          def self.find_dataset(api_key, dataset_name)
            response = Config.langsmith_request(
              method: :get,
              path: '/api/v1/datasets',
              query: { name: dataset_name },
              api_key: api_key
            )

            return unless response.success?

            datasets = ::Gitlab::Json.safe_parse(response.body)
            return unless datasets.is_a?(Array) && datasets.any?

            dataset = datasets.find { |d| d['dataset_name'] == dataset_name || d['name'] == dataset_name }
            return unless dataset

            dataset['id'] || dataset['dataset_id']
          rescue StandardError
            nil
          end

          def self.delete_dataset(api_key, dataset_id)
            response = Config.langsmith_request(
              method: :delete,
              path: "/api/v1/datasets/#{dataset_id}",
              api_key: api_key
            )

            if response.success?
              puts "Deleted existing dataset (ID: #{dataset_id})"
            else
              puts "Warning: Failed to delete existing dataset: #{response.code} #{response.message}"
            end
          rescue StandardError => e
            puts "Warning: Error deleting dataset: #{e.message}"
          end

          def self.add_examples_to_dataset(api_key, dataset_id, issue_data)
            # Create examples one at a time to match API expectations
            success_count = 0
            failure_count = 0

            issue_data.each_with_index do |data, index|
              # Only log progress every 10 examples or on the last one
              if (index + 1) % 10 == 0 || index + 1 == issue_data.size
                puts "  Adding examples: #{index + 1}/#{issue_data.size}..."
              end

              response = Config.langsmith_request(
                method: :post,
                path: '/api/v1/examples',
                body: {
                  dataset_id: dataset_id,
                  inputs: {
                    **data[:inputs]
                  },
                  outputs: {
                    **data[:outputs]
                  }
                },
                api_key: api_key
              )

              if response.success?
                success_count += 1
              else
                failure_count += 1
                puts "Failed to add example #{index + 1}: #{response.code} #{response.message}"
                puts "Response body: #{response.body}"
              end
            end

            puts "  Added #{success_count} examples successfully#{failure_count > 0 ? ", #{failure_count} failed" : ''}"
          rescue StandardError => e
            puts "Error adding examples to dataset: #{e.message}"
            puts e.backtrace.first(5).join("\n")
            raise
          end
        end
      end
    end
  end
end

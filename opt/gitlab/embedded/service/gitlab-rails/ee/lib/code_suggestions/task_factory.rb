# frozen_string_literal: true

module CodeSuggestions
  class TaskFactory
    include Gitlab::Utils::StrongMemoize

    def initialize(current_user, client:, params:, unsafe_passthrough_params: {})
      @current_user = current_user
      @client = client
      @params = params
      @unsafe_passthrough_params = unsafe_passthrough_params

      @content_above_cursor = params.dig(:current_file, :content_above_cursor)
      @content_below_cursor = params.dig(:current_file, :content_below_cursor)
      @intent = params[:intent]
    end

    def task
      trim_context!

      instruction = extract_instruction(CodeSuggestions::FileContent.new(language, content_above_cursor,
        content_below_cursor))

      return code_completion_task unless instruction

      code_generation_task(instruction)
    end

    private

    attr_reader :current_user, :client, :params, :unsafe_passthrough_params, :content_above_cursor,
      :content_below_cursor, :intent

    def extract_instruction(file_content)
      CodeSuggestions::InstructionsExtractor
        .new(file_content, intent, params[:generation_type], params[:user_instruction])
        .extract
    end

    def code_completion_task
      CodeSuggestions::Tasks::CodeCompletion.new(
        params: code_completion_params,
        unsafe_passthrough_params: unsafe_passthrough_params,
        current_user: current_user,
        client: client
      )
    end

    def code_generation_task(instruction)
      CodeSuggestions::Tasks::CodeGeneration.new(
        params: code_generation_params(instruction),
        unsafe_passthrough_params: unsafe_passthrough_params,
        current_user: current_user,
        client: client
      )
    end

    def language
      CodeSuggestions::ProgrammingLanguage.detect_from_filename(params.dig(:current_file, :file_name))
    end
    strong_memoize_attr(:language)

    def code_generation_params(instruction)
      params.merge(
        content_above_cursor: content_above_cursor,
        instruction: instruction,
        project: project,
        current_user: current_user
      )
    end

    def code_completion_params
      params.merge(
        project: project
      )
    end

    def project
      ::ProjectsFinder
        .new(
          params: { full_paths: [params[:project_path]] },
          current_user: current_user
        ).execute.first
    end
    strong_memoize_attr(:project)

    def trim_context!
      return if params[:context].blank?

      @params[:context] = Context.new(params[:context]).trimmed
    end
  end
end

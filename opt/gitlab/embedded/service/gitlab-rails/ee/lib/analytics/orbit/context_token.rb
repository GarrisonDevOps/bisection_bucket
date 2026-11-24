# frozen_string_literal: true

module Analytics
  module Orbit
    # Parses a context token from its text alone, before any database lookup.
    class ContextToken
      MERGE_REQUEST = 'MergeRequest'
      WORK_ITEM = 'WorkItem'
      JOB = 'Job'
      PIPELINE = 'Pipeline'
      BRANCH = 'Branch'
      COMMIT = 'Commit'
      # Match `Authz::RedactionService::RESOURCE_CLASSES` keys and the ontology `redaction.resource_type` values.
      REDACTION_TYPES = { MERGE_REQUEST => :merge_request, WORK_ITEM => :work_item }.freeze
      EPIC = 'Epic'
      # An epic resolves to its work item, so `Parsed#type` is WORK_ITEM and `Parsed#epic` marks the epic token.
      TYPES = {
        'mergerequest' => MERGE_REQUEST, 'workitem' => WORK_ITEM, 'issue' => WORK_ITEM, 'epic' => EPIC,
        'job' => JOB, 'ci::build' => JOB, 'pipeline' => PIPELINE, 'ci::pipeline' => PIPELINE
      }.freeze
      ID_URL_TYPES = [JOB, PIPELINE].freeze
      URL_SEGMENT_TYPES = {
        'merge_requests' => MERGE_REQUEST, 'issues' => WORK_ITEM, 'work_items' => WORK_ITEM, 'epics' => EPIC,
        'jobs' => JOB, 'pipelines' => PIPELINE
      }.freeze
      MAX_ID = 9_223_372_036_854_775_807
      MAX_IID = 2_147_483_647
      NUMBER = '[1-9][0-9]{0,18}'
      MAX_REF_LENGTH = 255
      SHA_PATTERN = /\A\h{7,64}\z/

      PATH_CONTAINERS = { '!' => :project, '#' => :any, '&' => :group }.freeze

      BRACKET_PATTERN = /\A(?<type>[A-Za-z][A-Za-z0-9]*)\[(?<id>#{NUMBER})\]\z/
      GID_PATTERN = %r{\Agid://gitlab/(?<type>[A-Za-z][A-Za-z0-9:]*)/(?<id>#{NUMBER})\z}
      PATH_PATTERN = %r{\A(?<path>[\w.-]+(?:/[\w.-]+)*)(?<sigil>[!#&])(?<iid>#{NUMBER})\z}
      URL_PATH_PATTERN = %r{\A/(?<groups>groups/)?(?<path>.+?)/-/(?<segment>[a-z_]+)/(?<iid>#{NUMBER})(?:/.*)?\z}
      # `path@ref` names a branch, or a commit when no branch has that name. Paths cannot contain `@`.
      REF_PATTERN = %r{\A(?<path>[\w.-]+(?:/[\w.-]+)*)@(?<ref>.+)\z}
      COMMIT_URL_PATTERN = %r{\A/(?<path>.+?)/-/commit/(?<sha>\h{7,64})/?\z}

      # `container` is :project, :group or :any and applies to iid lookups and job and pipeline URLs.
      # `ref` is set for branch and commit tokens, which resolve by name in the repository of `path`.
      Parsed = Data.define(:type, :id, :iid, :path, :container, :epic, :error, :ref) do
        def initialize(ref: nil, **attributes)
          super
        end

        def iid_lookup?
          iid.present?
        end

        def ref_lookup?
          ref.present?
        end
      end

      def self.commit_sha?(ref)
        SHA_PATTERN.match?(ref)
      end

      def self.parse(token)
        new(token).parse
      end

      def initialize(token)
        @token = token.to_s.strip
      end

      def parse
        match = BRACKET_PATTERN.match(token) || GID_PATTERN.match(token)
        return id_token(match) if match

        match = PATH_PATTERN.match(token)
        return path_token(match) if match

        match = REF_PATTERN.match(token)
        return ref_token(match[:path], match[:ref], BRANCH) if match

        token.match?(%r{\Ahttps?://}i) ? url_token : error('invalid_token')
      end

      private

      attr_reader :token

      def id_token(match)
        type = TYPES[match[:type].downcase]
        return error('unsupported_type') unless type

        id = match[:id].to_i
        return error('invalid_token') if id > MAX_ID

        Parsed.new(
          type: type == EPIC ? WORK_ITEM : type, id: id, iid: nil, path: nil, container: nil, epic: type == EPIC,
          error: nil
        )
      end

      def path_token(match)
        iid = match[:iid].to_i
        return error('invalid_token') if iid > MAX_IID

        sigil = match[:sigil]
        Parsed.new(
          type: sigil == '!' ? MERGE_REQUEST : WORK_ITEM, id: nil, iid: iid, path: match[:path],
          container: PATH_CONTAINERS.fetch(sigil), epic: sigil == '&', error: nil
        )
      end

      def ref_token(path, ref, type)
        return error('invalid_token') if ref.bytesize > MAX_REF_LENGTH || !Gitlab::GitRefValidator.validate(ref)

        Parsed.new(
          type: type, id: nil, iid: nil, path: path, container: :project, epic: false, error: nil, ref: ref
        )
      end

      def url_token
        uri = URI.parse(token)
        return error('invalid_token') unless same_instance?(uri)

        url_path = uri.path.delete_prefix(relative_url_root)
        commit = COMMIT_URL_PATTERN.match(url_path)
        return ref_token(commit[:path], commit[:sha], COMMIT) if commit

        match = URL_PATH_PATTERN.match(url_path)
        return error('invalid_token') unless match

        type = URL_SEGMENT_TYPES[match[:segment]]
        return error('unsupported_type') unless type
        return error('invalid_token') if type == EPIC && !match[:groups]
        return id_url_token(match, type) if ID_URL_TYPES.include?(type)

        iid = match[:iid].to_i
        return error('invalid_token') if iid > MAX_IID

        Parsed.new(
          type: type == EPIC ? WORK_ITEM : type, id: nil, iid: iid, path: match[:path],
          container: match[:groups] ? :group : :project, epic: type == EPIC, error: nil
        )
      rescue URI::InvalidURIError
        error('invalid_token')
      end

      def id_url_token(match, type)
        id = match[:iid].to_i
        return error('invalid_token') if id > MAX_ID

        Parsed.new(type: type, id: id, iid: nil, path: match[:path], container: :project, epic: false, error: nil)
      end

      def same_instance?(uri)
        instance = URI.parse(Gitlab.config.gitlab.url)

        uri.scheme.to_s.casecmp?(instance.scheme) && uri.host.to_s.casecmp?(instance.host) &&
          uri.port == instance.port
      end

      def relative_url_root
        Gitlab.config.gitlab.relative_url_root.to_s
      end

      def error(code)
        Parsed.new(type: nil, id: nil, iid: nil, path: nil, container: nil, epic: false, error: code)
      end
    end
  end
end

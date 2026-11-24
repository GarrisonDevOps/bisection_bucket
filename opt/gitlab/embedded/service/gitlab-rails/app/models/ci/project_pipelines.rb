# frozen_string_literal: true

module Ci
  class ProjectPipelines
    def initialize(project)
      @project = project
    end

    # Pipelines from all sources, including dangling ones. See #filter for the options.
    def all_pipelines(**options)
      filter(scope, **options)
    end

    # Pipelines that contribute to the status of a ref. Excludes dangling
    # pipelines such as those from Web IDE or child pipelines.
    def ci_pipelines(**options)
      filter(scope.ci_sources, **options)
    end

    def find(id)
      all_pipelines.find(id)
    end

    def find_by_id(id)
      all_pipelines.find_by_id(id)
    end

    def latest(ref: nil, branch: nil, sha: nil)
      ci_pipelines(ref: ref, branch: branch, sha: sha, order: :id_desc).first
    end

    def latest_in_default_branch
      latest(ref: project.default_branch)
    end

    def any_ci_pipelines?
      ci_pipelines.exists?
    end

    def external_pull_request_pipelines
      for_builds_access(scope.external_pull_request_event)
    end

    # `auto_devops_source` filters `config_source`, so it does not exclude dangling pipelines by itself.
    def auto_devops_pipelines
      ci_pipelines.auto_devops_source
    end

    private

    attr_reader :project

    def scope
      ::Ci::Pipeline.for_project(project.id)
    end

    # `branch` is more specific than `ref`, which also matches tags, so only one of them can be given.
    def filter(pipelines, ref: nil, branch: nil, sha: nil, source: nil, order: nil, recent_partitions: false)
      raise ArgumentError, "Unsupported order: #{order}" unless order.nil? || order == :id_desc
      raise ArgumentError, 'Pass either ref or branch, not both' if ref && branch

      pipelines = pipelines.in_partition(::Ci::Partition.recent_ids) if recent_partitions
      pipelines = pipelines.for_ref(ref) if ref
      pipelines = pipelines.for_branch(branch) if branch
      pipelines = pipelines.for_sha(sha) if sha
      pipelines = pipelines.with_pipeline_source(source) if source
      pipelines = for_builds_access(pipelines)
      pipelines = pipelines.order_id_desc if order
      pipelines
    end

    # When CI/CD is disabled, only pipelines from external CI services remain visible.
    def for_builds_access(pipelines)
      project.builds_enabled? ? pipelines : pipelines.external
    end
  end
end

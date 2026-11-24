# frozen_string_literal: true

module Gitlab
  module LicenseScanning
    class BaseScanner
      attr_reader :project, :pipeline, :user

      # `user` scopes artifact reads to what the viewer may access (nil = guest, i.e.
      # public artifacts only). Internal/system callers pass `LicenseScanning::UNSCOPED`
      # (the default) to read every artifact.
      def initialize(project, pipeline, user = ::Gitlab::LicenseScanning::UNSCOPED)
        @project = project
        @pipeline = pipeline
        @user = user
      end

      def self.latest_pipeline(project, ref)
        raise "Must implement method in child class"
      end

      def report
        raise "Must implement method in child class"
      end

      def has_data?
        raise "Must implement method in child class"
      end

      def results_available?
        raise "Must implement method in child class"
      end

      def latest_build_for_default_branch
        raise "Must implement method in child class"
      end

      private

      def empty_report
        ::Gitlab::Ci::Reports::LicenseScanning::Report.new
      end
    end
  end
end

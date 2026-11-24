# frozen_string_literal: true

module Admin
  module Licenses
    class BillableUsageExportsController < Admin::ApplicationController
      include Admin::LicenseRequest

      before_action :require_license
      before_action :verify_export_available!
      before_action :verify_term_available!, except: :terms
      before_action :verify_period_available!, except: :terms

      feature_category :consumables_cost_management
      urgency :low

      def terms
        available_terms = Utilization::BillableUsage::Exports::Term.available
        render json: Utilization::BillableUsage::Exports::TermSerializer.new.represent(available_terms)
      end

      def show
        result = build_export
        return render_build_error(result) if result.error?

        render json: {
          document: result.payload[:document],
          licensed_seats: term.seats,
          last_exported_at: term.last_exported_at&.utc&.iso8601
        }
      end

      def download
        result = build_export
        return render_build_error(result) if result.error?

        record_export(result.payload[:document])
        set_license_usage_data_exported

        send_data(
          result.payload[:json],
          type: 'application/json; charset=utf-8',
          filename: "billable_usage_export_#{period.start_date.iso8601}_#{period.end_date.iso8601}.json"
        )
      end

      private

      def term
        if license_id.present?
          Utilization::BillableUsage::Exports::Term.find(license_id)
        else
          Utilization::BillableUsage::Exports::Term.current
        end
      end
      strong_memoize_attr :term

      def license_id
        params.permit(:license_id)[:license_id]
      end

      def period
        term.period
      end

      def build_export
        Utilization::BillableUsage::Exports::BuildPayloadService.new(period: period, license: term.license).execute
      end

      def render_build_error(result)
        render json: { message: result.message }, status: :unprocessable_entity
      end

      def record_export(document)
        Utilization::BillableUsage::ExportLog.create!(
          period_start: period.start_date,
          period_end: period.end_date,
          generated_at: document['generated_at'],
          generated_by: current_user,
          record_count: document['record_count'],
          payload_checksum: document['checksum']
        )
      end

      def set_license_usage_data_exported
        return unless term.current?

        Gitlab::CurrentSettings.update(license_usage_data_exported: true)
      end

      def verify_export_available!
        render_404 unless ::Utilization::BillableUsage::Exports::Availability.enabled?
      end

      def verify_term_available!
        render_404 unless term
      end

      # On the day a license starts no day has completed, and the export log rejects a
      # period that ends before it starts.
      def verify_period_available!
        return unless period.empty?

        render json: { message: s_('BillableUsageExport|There is no completed day to export yet') },
          status: :unprocessable_entity
      end
    end
  end
end

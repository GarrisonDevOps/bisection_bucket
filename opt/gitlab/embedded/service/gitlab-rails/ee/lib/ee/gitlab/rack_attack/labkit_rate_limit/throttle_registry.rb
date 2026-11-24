# frozen_string_literal: true

module EE
  module Gitlab
    module RackAttack
      module LabkitRateLimit
        # Extends the CE shadow registry with the EE-only middleware throttles so
        # Labkit::RateLimit shadows (and can enforce) them alongside the CE ones.
        module ThrottleRegistry
          extend ActiveSupport::Concern

          # throttle_incident_management_notification_web counts by request path
          # and needs its own limiter: alerts_notify? requires web_request?, so the
          # throttle always co-fires with the general web throttle and Rack::Attack
          # counts the request under both. Sharing the general limiter would let
          # only one of the two rules match per request, under-counting the other.
          # Mirrors why protected paths have their own limiter.
          INCIDENT_MANAGEMENT_LIMITER = 'rack_request_incident_management'

          # alerts_notify? is `web_request? && logical_path.include?('alerts/notify')`.
          # Both halves fold into one path matcher, so the rule needs no separate web
          # fact: the negative lookaheads are WEB_PATH_REGEX's (a web path is neither an
          # API path - ^/api/ or /oauth/ anywhere - nor the health family), followed by
          # `.*alerts/notify` for the substring. MULTILINE so the unanchored `/oauth/`
          # scan crosses newlines as the predicate's #match? does. A parity spec pins
          # this to alerts_notify? over a path table. The path discriminator is always
          # present, so the rule needs no presence gate.
          ALERTS_NOTIFY_PATH_REGEX = Regexp.new(
            '\A(?!.*/oauth/)(?!/api/)(?!/-/(?:health|liveness|readiness|metrics)).*alerts/notify',
            Regexp::MULTILINE
          )

          # Promoted in cohort 1 (the lowest-risk, specialized bucket), reusing that
          # cohort's existing shadow/enforce flag pair.
          EE_META = {
            'throttle_incident_management_notification_web' => {
              limiter: INCIDENT_MANAGEMENT_LIMITER, characteristics: [:path], cohort: 1, claims: true,
              match: { setting_incident_management_notification: true, path: ALERTS_NOTIFY_PATH_REGEX }
            }
          }.freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :meta
            def meta
              super.merge(EE_META)
            end

            # EE's should_be_skipped? also folds in the virtual-registry endpoints (a
            # path) and the geo-JWT checks (not a path), each keyed by its own name so
            # it is its own rule, mirroring how CE splits its path skips.
            override :skip_matches
            def skip_matches
              super.merge(
                'skip_virtual_registries' => {
                  requester_id: nil, runner_id: nil,
                  path: ::EE::Gitlab::RateLimit::RequestClassification::VIRTUAL_REGISTRIES_API_ENDPOINTS_REGEX
                },
                'skip_geo' => { verified_geo_request: true, requester_id: nil, runner_id: nil }
              )
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

# Wires the Policy Store facade (gems/gitlab-policy-store) to its persistent
# ActiveRecord backend. This file ships only in EE; the gem has no default
# backend, so in FOSS the facade raises NotConfigured. Nothing in FOSS calls it.
Rails.application.config.to_prepare do
  Gitlab::PolicyStore.configure do |config|
    config.repository = Govern::PolicyStore::ActiveRecordPolicyRepository.new
    config.evaluation_recorder = Govern::PolicyStore::ActiveRecordEvaluationRecorder.new
  end
end

# frozen_string_literal: true

class DataSeeder
  GROUP_CONFIGS = [
    { plan: :ultimate },
    { plan: :ultimate, add_on: { name: :duo_enterprise } },
    { plan: :ultimate, add_on: { name: :duo_enterprise, trial: true, expired: true } },
    { plan: :ultimate, trial: true, add_on: { name: :duo_enterprise, trial: true } },
    { plan: :ultimate, trial: true, expired: true, add_on: { name: :duo_enterprise, trial: true, expired: true } },
    { plan: :premium },
    { plan: :premium, add_on: { name: :code_suggestions } },
    { plan: :premium, add_on: { name: :code_suggestions, trial: true } },
    { plan: :premium_trial, trial: true, expired: true, add_on: { name: :code_suggestions, trial: true } }
  ].freeze

  def seed
    unless ::Gitlab::Saas.feature_available?(:subscriptions_trials)
      return @logger.info "Env must be be setup to support subscription trials"
    end

    team = fetch_team
    groups = GROUP_CONFIGS.map do |uc|
      group = create(:group_with_plan, params_for_namespace(uc))
      add_team_as_owners(group, team)

      next group unless uc[:add_on].present?

      add_on_id = GitlabSubscriptions::SystemDefined::AddOn.find_by(name: uc.dig(:add_on, :name).to_s).id # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn

      # TODO: build+save! works here but create causes a unique name validation error (they should be equivalent)
      build(:gitlab_subscription_add_on_purchase, uc.dig(:add_on, :expired) ? :expired : :active, namespace: group,
        subscription_add_on_uid: add_on_id, trial: uc.dig(:add_on, :trial) || false).save!

      group
    end

    puts "\n\nGroups created:\n\n"
    groups.each do |g|
      name = g.name[@group.name.length..]
      config = Gitlab.config.gitlab
      puts "\t#{name} → http#{config.https && 's'}://#{config.host}:#{config.port}/groups/#{g.path}\n"
    end
  end

  private

  def params_for_namespace(uc)
    name = namespace_name(uc)
    params = { name: "#{@group.name} #{name.titlecase}", path: "#{@group.path}-#{name.parameterize}",
               plan: "#{uc[:plan]}_plan", trial: uc[:trial] || false }
    params.merge!({ trial_starts_on: 1.day.ago, trial_ends_on: 10.days.from_now }) if uc[:trial]
    params.merge!({ trial_starts_on: 10.days.ago, trial_ends_on: 1.day.ago }) if uc[:expired]
    params
  end

  def namespace_name(uc)
    [uc[:plan], uc[:expired] && "expired", uc.dig(:add_on, :name),
      uc.dig(:add_on, :trial) && "trial", uc.dig(:add_on, :expired) && "expired"].compact.join(" ")
  end

  def add_team_as_owners(namespace, team)
    team.each do |team_member|
      user = User.find_by(username: team_member) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
      next unless user

      namespace.add_owner(user)
    end
  end

  def fetch_team
    response = Faraday.get('https://about.gitlab.com/company/team/')

    return @logger.info "Fetching team members page failed" unless response.status == 200

    doc = Nokogiri::HTML(response.body)
    doc.css('div.member').filter_map do |div|
      team_name = div.css('h5').text.strip

      div.css('a.member-id').first['href'][1..] if team_name.include?('Growth: Acquisition')
    end
  end
end

# frozen_string_literal: true

module Projects
  # The topic names assigned to a project with `Project#topic_list=`, as a
  # comma-separated string or an array, and the topics they resolve to.
  class TopicList
    def initialize(project, value)
      @project = project
      @value = value
    end

    # Stripped, without blank names. Topics are looked up by name
    # case-insensitively, so a name that differs from an earlier one only in
    # case repeats it and is dropped.
    def names
      @names ||= (value.instance_of?(String) ? value.split(',') : value)
        .map(&:strip).uniq(&:downcase).reject(&:empty?)
    end

    # The topic of each name, created when the organization has none yet.
    def topics
      names.map do |name|
        topics_in_organization
          .where('lower(name) = lower(?)', name)
          .order(total_projects_count: :desc)
          .first_or_create(new_topic_attributes(name))
      end
    end

    # Topics are created after the project is saved, where a topic that fails
    # its own validation can only abort the save. Report each new topic that
    # would fail as an error on topics, so the project fails validation instead.
    def validate_new_topics
      return if names.empty?

      existing_names = topics_in_organization
        .where(Projects::Topic.arel_table[:name].lower.in(names.map { |name| lower(name) }))
        .distinct
        .limit(names.size)
        .pluck(Arel.sql('lower(name)'))
        .to_set
      new_slugs = Set.new

      names.each do |name|
        next if existing_names.include?(name.downcase)

        topic = Projects::Topic.new(organization_id: project.organization_id, **new_topic_attributes(name))
        topic.validate
        # Ruby and PostgreSQL lowercase some letters differently (U+0130), so
        # the check above can miss a topic that exists. It is reused, not new.
        next if topic.errors.of_kind?(:name, :taken)

        # The new topics are created one after another, so a slug that an
        # earlier one takes is taken for the later ones too.
        unless new_slugs.add?(topic.slug.downcase) || topic.errors.of_kind?(:slug, :taken)
          topic.errors.add(:slug, :taken)
        end

        next if topic.errors.empty?

        project.errors.add(:topics, format(s_("Topics|'%{name}' is invalid: %{reason}"),
          name: name, reason: topic.errors.full_messages.to_sentence))
      end
    end

    private

    attr_reader :project, :value

    def topics_in_organization
      Projects::Topic.in_organization(project.organization_id)
    end

    def new_topic_attributes(name)
      { name: name, title: name, slug: Gitlab::Slug::Path.new(name).generate }
    end

    def lower(value)
      Arel::Nodes::NamedFunction.new('LOWER', [Arel::Nodes.build_quoted(value)])
    end
  end
end

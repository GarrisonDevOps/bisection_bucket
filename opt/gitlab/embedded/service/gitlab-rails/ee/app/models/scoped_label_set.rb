# frozen_string_literal: true

class ScopedLabelSet
  attr_reader :labels, :key

  def self.from_label_ids(ids)
    by_key = Hash.new { |hash, key| hash[key] = new(key) }
    labels = Label.select(:id, :title, :lock_on_merge).where(id: ids)

    labels.each do |label|
      key = label.scoped_label_key
      by_key[key].add(label)
    end

    by_key.values
  end

  # When a scope would hold several labels and one of them is being added, keeps only the
  # last selected one. With lock_on_merge, drops the additions to a locked scope instead.
  def self.filter_mutually_exclusive(
    label_ids, existing_label_ids:, label_ids_ordered_by_selection:, lock_on_merge: false
  )
    added_label_ids = label_ids - existing_label_ids
    return label_ids if added_label_ids.empty?

    from_label_ids(label_ids).flat_map do |set|
      if set.valid? || !set.contains_any?(added_label_ids)
        set.label_ids
      elsif lock_on_merge && set.lock_on_merge_labels?
        set.label_ids - added_label_ids
      else
        set.last_id_by_order(label_ids_ordered_by_selection)
      end
    end
  end

  def initialize(key, labels = [])
    @key = key
    @labels = labels
  end

  def add(label)
    labels << label
  end

  def last_id_by_order(label_ids_order)
    by_index = label_ids_order.map.with_index { |id, idx| [id.to_i, idx] }.to_h

    label_ids.max do |id1, id2|
      by_index.fetch(id1, -1) <=> by_index.fetch(id2, -1)
    end
  end

  def valid?
    key.nil? || labels.count < 2
  end

  def contains_any?(ids)
    (label_ids & ids).present?
  end

  def label_ids
    labels.map(&:id)
  end

  def lock_on_merge_labels?
    labels.any?(&:lock_on_merge)
  end
end

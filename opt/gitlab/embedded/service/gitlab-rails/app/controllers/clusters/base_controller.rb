# frozen_string_literal: true

class Clusters::BaseController < ApplicationController
  include RoutableActions

  skip_before_action :authenticate_user!
  before_action :clusterable
  before_action :authorize_admin_cluster!, except: [:show, :index, :new, :authorize_aws_role, :update]

  helper_method :clusterable

  feature_category :deployment_management
  urgency :low, [
    :index, :show, :environments, :cluster_status,
    :destroy, :new_cluster_docs, :connect, :new, :create_user
  ]

  private

  def cluster
    @cluster ||= clusterable.clusters.find(params.permit(:id)[:id])
                                 .present(current_user: current_user)
  end

  def authorize_update_cluster!
    access_denied! unless can?(current_user, :update_cluster, clusterable)
  end

  def authorize_admin_cluster!
    access_denied! unless can?(current_user, :admin_cluster, clusterable)
  end

  def authorize_read_cluster!
    access_denied! unless can?(current_user, :read_cluster, clusterable)
  end

  def authorize_create_cluster!
    access_denied! unless can?(current_user, :create_cluster, clusterable)
  end

  def authorize_read_prometheus!
    access_denied! unless can?(current_user, :read_prometheus, clusterable)
  end

  # Group and project clusterables use `find_routable!`, which renders a 404 without access.
  # Call `clusterable` in its own before_action before the `authorize_*` ones,
  # so a 404 is rendered and the `authorize_*` calls never run.
  def clusterable
    raise NotImplementedError
  end
end

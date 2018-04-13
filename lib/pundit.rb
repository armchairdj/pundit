require "pundit/version"
require "pundit/policy_finder"
require "active_support/concern"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/module/introspection"
require "active_support/dependencies/autoload"

module Pundit
  SUFFIX = "Policy".freeze

  module Generators; end

  class Error < StandardError; end
  class NotAuthorizedError < Error
    attr_reader :query, :record, :policy

    def initialize(options = {})
      if options.is_a? String
        message = options
      else
        @query  = options[:query]
        @record = options[:record]
        @policy = options[:policy]

        message = options.fetch(:message) { "not allowed to #{query} this #{record.inspect}" }
      end

      super(message)
    end
  end
  class AuthorizationNotPerformedError < Error; end
  class PolicyScopingNotPerformedError < AuthorizationNotPerformedError; end
  class NotDefinedError < Error; end

  extend ActiveSupport::Concern

  class << self
    def authorize(user, record, query)
      policy = policy!(user, record, self.parent)

      unless policy.public_send(query)
        raise NotAuthorizedError, query: query, record: record, policy: policy
      end

      record
    end

    def policy!(user, record, namespace = Object)
      puts ">>klass.policy!", namespace

      PolicyFinder.new(record, namespace).policy!.new(user, record)
    end

    def policy(user, record, namespace = Object)
      policy = PolicyFinder.new(record, namespace).policy

      policy.new(user, record) if policy
    end

    def policy_scope!(user, scope, namespace = Object)
      PolicyFinder.new(scope, namespace).scope!.new(user, scope).resolve
    end

    def policy_scope(user, scope, namespace = Object)
      policy_scope = PolicyFinder.new(scope, namespace).scope

      policy_scope.new(user, scope).resolve if policy_scope
    end
  end

  module Helper
    def policy_scope(scope)
      pundit_policy_scope(scope)
    end
  end

  included do
    helper Helper if respond_to?(:helper)

    if respond_to?(:helper_method)
      helper_method :policy
      helper_method :pundit_policy_scope
      helper_method :pundit_user
    end
  end

protected

  def authorize(record, query = nil)
    query ||= params[:action].to_s + "?"

    @_pundit_policy_authorized = true

    policy = policy(record)

    unless policy.public_send(query)
      raise NotAuthorizedError, query: query, record: record, policy: policy
    end

    record
  end

  def policy(record)
    parent = self.class.parent

    policies[parent]         ||= {}

    puts "present?", policies[parent][record].present?


    policies[parent][record] ||= Pundit.policy!(pundit_user, record, parent)

    puts ">>#policy"
    puts parent
    puts policies[parent][record].class
    puts "<<"

    policies[parent][record]
  end

  def policies
    @_pundit_policies ||= {}
  end

  def policy_scope(scope)
    @_pundit_policy_scoped = true

    pundit_policy_scope(scope)
  end

  def policy_scopes
    @_pundit_policy_scopes ||= {}
  end

  def permitted_attributes(record, action = params[:action])
    namespace = self.class.parent
    param_key = PolicyFinder.new(record, namespace).param_key
    policy    = policy(record)

    method_name = if policy.respond_to?("permitted_attributes_for_#{action}")
      "permitted_attributes_for_#{action}"
    else
      "permitted_attributes"
    end

    params.require(param_key).permit(*policy.public_send(method_name))
  end

  def pundit_user
    current_user
  end

  def skip_authorization
    @_pundit_policy_authorized = true
  end

  def skip_policy_scope
    @_pundit_policy_scoped = true
  end

  def verify_authorized
    raise AuthorizationNotPerformedError, self.class unless pundit_policy_authorized?
  end

  def verify_policy_scoped
    raise PolicyScopingNotPerformedError, self.class unless pundit_policy_scoped?
  end

  def pundit_policy_authorized?
    !!@_pundit_policy_authorized
  end

  def pundit_policy_scoped?
    !!@_pundit_policy_scoped
  end

private

  def pundit_policy_scope(scope)
    parent = self.class.parent

    policy_scopes[parent]        ||= {}
    policy_scopes[parent][scope] ||= Pundit.policy_scope!(pundit_user, scope, parent)
  end
end

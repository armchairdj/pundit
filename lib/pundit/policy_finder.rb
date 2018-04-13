module Pundit
  class PolicyFinder
    attr_reader :object, :namespace

    def initialize(object, namespace = Object)
      @object    = object
      @namespace = namespace
    end

    def policy!
      raise NotDefinedError, "unable to find policy of nil" if object.nil?

      policy or raise NotDefinedError, "unable to find policy `#{find}` for `#{object.inspect}`"
    end

    def policy
      klass = find
      klass = namespace.const_get(klass.demodulize) if klass.is_a?(String)
      klass
    rescue NameError
      nil
    end

    def scope
      policy::Scope if policy
    rescue NameError
      nil
    end

    def scope!
      raise NotDefinedError, "unable to find policy scope of nil" if object.nil?

      scope or raise NotDefinedError, "unable to find scope `#{find}::Scope` for `#{object.inspect}`"
    end

    def param_key
      if object.respond_to?(:model_name)
        object.model_name.param_key.to_s
      elsif object.is_a?(Class)
        object.to_s.demodulize.underscore
      else
        object.class.to_s.demodulize.underscore
      end
    end

  private

    def find
      if object.nil?
        nil
      elsif object.respond_to?(:policy_class)
        object.policy_class
      elsif object.class.respond_to?(:policy_class)
        object.class.policy_class
      else
        klass = if object.is_a?(Array)
          object.map { |x| find_class_name(x) }.join("::")
        else
          find_class_name(object)
        end

        "#{klass}#{SUFFIX}"
      end
    end

    def find_class_name(subject)
      if subject.respond_to?(:model_name)
        subject.model_name
      elsif subject.class.respond_to?(:model_name)
        subject.class.model_name
      elsif subject.is_a?(Class)
        subject
      elsif subject.is_a?(Symbol)
        subject.to_s.camelize
      else
        subject.class
      end
    end
  end
end

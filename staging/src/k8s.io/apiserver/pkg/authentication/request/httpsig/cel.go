/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpsig

import (
	"context"
	"fmt"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// This file compiles and evaluates the expressions of one certificate
// authenticator: the rules a certificate must satisfy, the mappings that turn it
// into an identity, and the rules that identity must satisfy.
//
// Compilation is exported, because configuration validation and the authenticator
// both need it and a second copy of these rules would drift from this one. It is
// the same arrangement the JWT authenticator uses for the same reason.

// CompileCertificateAuthenticator compiles the expressions of one certificate
// authenticator. It is exported so configuration validation rejects an
// unusable expression at server start, using the same code the authenticator
// runs, rather than a second copy of the same rules.
func CompileCertificateAuthenticator(compiler authenticationcel.Compiler, c apiserver.HTTPSignatureAuthenticator) (authenticationcel.CertificateCELMapper, error) {
	var mapper authenticationcel.CertificateCELMapper
	if compiler == nil {
		compiler = authenticationcel.NewDefaultCompiler()
	}

	if len(c.CertificateValidationRules) > 0 {
		compiled := make([]authenticationcel.CompilationResult, 0, len(c.CertificateValidationRules))
		for i, rule := range c.CertificateValidationRules {
			result, err := compiler.CompileCertificateExpression(&authenticationcel.CertificateValidationCondition{
				Expression: rule.Expression,
				Message:    rule.Message,
			})
			if err != nil {
				return mapper, fmt.Errorf("certificateValidationRules[%d].expression: %w", i, err)
			}
			compiled = append(compiled, result)
		}
		mapper.CertificateValidationRules = authenticationcel.NewCertificateMapper(compiled)
	}

	if c.ClaimMappings == nil {
		return mapper, fmt.Errorf("claimMappings is required")
	}
	m := c.ClaimMappings

	if m.Username.Expression == "" {
		return mapper, fmt.Errorf("claimMappings.username.expression is required")
	}
	for _, single := range []struct {
		path string
		expr string
		into *authenticationcel.CertificateMapper
	}{
		{"claimMappings.username.expression", m.Username.Expression, &mapper.Username},
		{"claimMappings.groups.expression", m.Groups.Expression, &mapper.Groups},
		{"claimMappings.uid.expression", m.UID.Expression, &mapper.UID},
	} {
		if single.expr == "" {
			continue
		}
		result, err := compiler.CompileCertificateExpression(&authenticationcel.CertificateMappingExpression{Expression: single.expr})
		if err != nil {
			return mapper, fmt.Errorf("%s: %w", single.path, err)
		}
		*single.into = authenticationcel.NewCertificateMapper([]authenticationcel.CompilationResult{result})
	}

	if len(m.Extra) > 0 {
		compiled := make([]authenticationcel.CompilationResult, 0, len(m.Extra))
		for i, extra := range m.Extra {
			result, err := compiler.CompileCertificateExpression(&authenticationcel.CertificateMappingExpression{
				Key:        extra.Key,
				Expression: extra.ValueExpression,
			})
			if err != nil {
				return mapper, fmt.Errorf("claimMappings.extra[%d].valueExpression: %w", i, err)
			}
			compiled = append(compiled, result)
		}
		mapper.Extra = authenticationcel.NewCertificateMapper(compiled)
	}

	if len(c.UserValidationRules) > 0 {
		compiled := make([]authenticationcel.CompilationResult, 0, len(c.UserValidationRules))
		for i, rule := range c.UserValidationRules {
			result, err := compiler.CompileUserExpression(&authenticationcel.UserValidationCondition{
				Expression: rule.Expression,
				Message:    rule.Message,
			})
			if err != nil {
				return mapper, fmt.Errorf("userValidationRules[%d].expression: %w", i, err)
			}
			compiled = append(compiled, result)
		}
		mapper.UserValidationRules = authenticationcel.NewUserMapper(compiled)
	}
	return mapper, nil
}

// evaluateCertificateRules runs the rules a certificate must satisfy. It fails on
// the first rule that returns false, so an error names one rule rather than a set.
func evaluateCertificateRules(ctx context.Context, rules authenticationcel.CertificateMapper, cert traits.Mapper) error {
	results, err := rules.EvalCertificateMappings(ctx, cert)
	if err != nil {
		return fmt.Errorf("evaluating certificateValidationRules: %w", err)
	}
	for _, result := range results {
		if result.EvalResult.Type().TypeName() != celgo.BoolType.TypeName() {
			return fmt.Errorf("certificateValidationRules expression must return a boolean")
		}
		if result.EvalResult.Value() == true {
			continue
		}
		condition, ok := result.ExpressionAccessor.(*authenticationcel.CertificateValidationCondition)
		if ok && condition.Message != "" {
			return fmt.Errorf("certificate rejected: %s", condition.Message)
		}
		return fmt.Errorf("certificate rejected: rule %q returned false", result.ExpressionAccessor.GetExpression())
	}
	return nil
}

// evaluateUserRules runs the rules the mapped identity must satisfy.
func evaluateUserRules(ctx context.Context, rules authenticationcel.UserMapper, info user.Info) error {
	results, err := rules.EvalUser(ctx, userInfoValue(info))
	if err != nil {
		return fmt.Errorf("evaluating userValidationRules: %w", err)
	}
	for _, result := range results {
		if result.EvalResult.Type().TypeName() != celgo.BoolType.TypeName() {
			return fmt.Errorf("userValidationRules expression must return a boolean")
		}
		if result.EvalResult.Value() == true {
			continue
		}
		condition, ok := result.ExpressionAccessor.(*authenticationcel.UserValidationCondition)
		if ok && condition.Message != "" {
			return fmt.Errorf("identity rejected: %s", condition.Message)
		}
		return fmt.Errorf("identity rejected: rule %q returned false", result.ExpressionAccessor.GetExpression())
	}
	return nil
}

// checkReservedIdentity rejects a mapped identity that asserts something this
// authenticator is not the one to decide.
//
// The list is three names, and it is deliberately not a ban on the "system:"
// prefix. Everything else, including system:masters, is left to
// userValidationRules, where an operator states it as a rule against their own
// deployment's mappings. A hardcoded policy list here would be a third copy of a
// guard the static key list and the JWT authenticator each answer differently, and
// the layer that should own it is an open question.
//
// What is left is not policy. These three are asserted by the authentication
// framework according to what it decided, so an authenticator claiming one is
// stating a falsehood rather than making a choice: the framework adds
// system:authenticated or system:unauthenticated according to whether
// authentication succeeded, and system:anonymous is what the anonymous
// authenticator asserts about a request that carried no credential.
//
// The check is on the evaluated output rather than on the expression, because a
// mapping such as 'cert.subject.organization' derives the value from the
// certificate, which puts the choice in the hands of whoever can request one.
// Reviewing expression text would catch a literal and miss that.
func checkReservedIdentity(info *user.DefaultInfo) error {
	if info.Name == user.Anonymous {
		return fmt.Errorf("claimMappings produced the username %q, which the anonymous authenticator asserts about a request that carried no credential", user.Anonymous)
	}
	for _, group := range info.Groups {
		switch group {
		case user.AllAuthenticated, user.AllUnauthenticated:
			return fmt.Errorf("claimMappings produced the group %q, which the server adds according to whether authentication succeeded and an authenticator may not claim", group)
		}
	}
	return nil
}

// mapIdentity turns a certificate into the identity a request authenticates as.
func (r *certificateResolver) mapIdentity(ctx context.Context, cert traits.Mapper) (*user.DefaultInfo, error) {
	info := &user.DefaultInfo{}

	name, err := evalString(ctx, r.mapper.Username, cert, "claimMappings.username")
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("claimMappings.username produced an empty user name")
	}
	info.Name = name

	if r.mapper.UID != nil {
		uid, err := evalString(ctx, r.mapper.UID, cert, "claimMappings.uid")
		if err != nil {
			return nil, err
		}
		info.UID = uid
	}

	if r.mapper.Groups != nil {
		result, err := r.mapper.Groups.EvalCertificateMapping(ctx, cert)
		if err != nil {
			return nil, fmt.Errorf("evaluating claimMappings.groups: %w", err)
		}
		groups, err := stringOrStringList(result.EvalResult, "claimMappings.groups")
		if err != nil {
			return nil, err
		}
		info.Groups = groups
	}

	if r.mapper.Extra != nil {
		results, err := r.mapper.Extra.EvalCertificateMappings(ctx, cert)
		if err != nil {
			return nil, fmt.Errorf("evaluating claimMappings.extra: %w", err)
		}
		for _, result := range results {
			expression, ok := result.ExpressionAccessor.(*authenticationcel.CertificateMappingExpression)
			if !ok {
				return nil, fmt.Errorf("claimMappings.extra produced a result with no key")
			}
			values, err := stringOrStringList(result.EvalResult, fmt.Sprintf("claimMappings.extra[%q]", expression.Key))
			if err != nil {
				return nil, err
			}
			// An empty value is the mapping not being present, rather than an
			// extra attribute with no value.
			if len(values) == 0 {
				continue
			}
			if info.Extra == nil {
				info.Extra = map[string][]string{}
			}
			info.Extra[expression.Key] = values
		}
	}
	return info, nil
}

func evalString(ctx context.Context, mapper authenticationcel.CertificateMapper, cert traits.Mapper, path string) (string, error) {
	result, err := mapper.EvalCertificateMapping(ctx, cert)
	if err != nil {
		return "", fmt.Errorf("evaluating %s: %w", path, err)
	}
	if result.EvalResult.Type().TypeName() != celgo.StringType.TypeName() {
		return "", fmt.Errorf("%s must produce a string, got %s", path, result.EvalResult.Type().TypeName())
	}
	value, ok := result.EvalResult.Value().(string)
	if !ok {
		return "", fmt.Errorf("%s must produce a string", path)
	}
	return value, nil
}

// stringOrStringList accepts either form a mapping may produce. "", [], and null
// all mean the mapping is not present, and empty strings inside a list are
// dropped, which matches how the JWT authenticator reads the same shapes.
//
// The list is read through traits.Lister rather than by switching on the Go type
// backing it. The JWT authenticator switches on []interface{} versus []ref.Val
// and errors on anything else, which is a claim about how cel-go represents a
// list rather than about what the expression returned.
func stringOrStringList(value ref.Val, path string) ([]string, error) {
	switch value.Type().TypeName() {
	case celgo.StringType.TypeName():
		s, ok := value.Value().(string)
		if !ok {
			return nil, fmt.Errorf("%s must produce a string or a list of strings", path)
		}
		if s == "" {
			return nil, nil
		}
		return []string{s}, nil

	case celgo.NullType.TypeName():
		return nil, nil

	case celgo.ListType(nil).TypeName():
		lister, ok := value.(traits.Lister)
		if !ok {
			return nil, fmt.Errorf("%s must produce a string or a list of strings", path)
		}
		size, ok := lister.Size().Value().(int64)
		if !ok {
			return nil, fmt.Errorf("%s produced a list of unknown length", path)
		}
		out := make([]string, 0, size)
		for i := int64(0); i < size; i++ {
			item := lister.Get(types.Int(i))
			s, ok := item.Value().(string)
			if !ok {
				return nil, fmt.Errorf("%s must produce a list of strings, and item %d is a %s", path, i, item.Type().TypeName())
			}
			if s == "" {
				continue
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil

	default:
		return nil, fmt.Errorf("%s must produce a string or a list of strings, got %s", path, value.Type().TypeName())
	}
}

// userInfoValue is the value a user validation rule evaluates against. The type
// name matches what the CEL environment declares, and the fields match the four
// it declares.
func userInfoValue(info user.Info) traits.Mapper {
	lazyMap := lazy.NewMapValue(types.NewObjectType("kubernetes.UserInfo"))
	field := func(name string, get func() any) {
		lazyMap.Append(name, func(_ *lazy.MapValue) ref.Val {
			return types.DefaultTypeAdapter.NativeToValue(get())
		})
	}
	field("username", func() any { return info.GetName() })
	field("uid", func() any { return info.GetUID() })
	field("groups", func() any { return info.GetGroups() })
	field("extra", func() any { return info.GetExtra() })
	return lazyMap
}

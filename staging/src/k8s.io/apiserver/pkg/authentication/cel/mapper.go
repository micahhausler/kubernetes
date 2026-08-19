/*
Copyright 2023 The Kubernetes Authors.

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

package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
)

var _ ClaimsMapper = &mapper{}
var _ UserMapper = &mapper{}
var _ CertificateMapper = &mapper{}

// mapper implements the ClaimsMapper, UserMapper and CertificateMapper
// interfaces. The three differ only in which variable name they bind, so one
// implementation serves all of them.
type mapper struct {
	compilationResults []CompilationResult
}

// CELMapper is a struct that holds the compiled expressions for
// username, groups, uid, extra, claimValidation and userValidation
type CELMapper struct {
	Username             ClaimsMapper
	Groups               ClaimsMapper
	UID                  ClaimsMapper
	Extra                ClaimsMapper
	ClaimValidationRules ClaimsMapper
	UserValidationRules  UserMapper
}

// CertificateCELMapper holds the compiled expressions of one certificate
// authenticator: the rules a certificate must satisfy, the mappings that turn it
// into an identity, and the rules that identity must satisfy.
//
// It is separate from CELMapper rather than added to it because the two share no
// field. CELMapper's mappings read claims and this one's read a certificate, so a
// single struct would have twice the fields and half of them always nil.
type CertificateCELMapper struct {
	CertificateValidationRules CertificateMapper
	Username                   CertificateMapper
	Groups                     CertificateMapper
	UID                        CertificateMapper
	Extra                      CertificateMapper
	UserValidationRules        UserMapper
}

// NewClaimsMapper returns a new ClaimsMapper.
func NewClaimsMapper(compilationResults []CompilationResult) ClaimsMapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

// NewUserMapper returns a new UserMapper.
func NewUserMapper(compilationResults []CompilationResult) UserMapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

// NewCertificateMapper returns a new CertificateMapper.
func NewCertificateMapper(compilationResults []CompilationResult) CertificateMapper {
	return &mapper{
		compilationResults: compilationResults,
	}
}

// EvalClaimMapping evaluates the given claim mapping expression and returns a EvaluationResult.
func (m *mapper) EvalClaimMapping(ctx context.Context, claims traits.Mapper) (EvaluationResult, error) {
	results, err := m.eval(ctx, &varNameActivation{name: claimsVarName, value: claims})
	if err != nil {
		return EvaluationResult{}, err
	}
	if len(results) != 1 {
		return EvaluationResult{}, fmt.Errorf("expected 1 evaluation result, got %d", len(results))
	}
	return results[0], nil
}

// EvalClaimMappings evaluates the given expressions and returns a list of EvaluationResult.
func (m *mapper) EvalClaimMappings(ctx context.Context, claims traits.Mapper) ([]EvaluationResult, error) {
	return m.eval(ctx, &varNameActivation{name: claimsVarName, value: claims})
}

// EvalUser evaluates the given user expressions and returns a list of EvaluationResult.
func (m *mapper) EvalUser(ctx context.Context, userInfo traits.Mapper) ([]EvaluationResult, error) {
	return m.eval(ctx, &varNameActivation{name: userVarName, value: userInfo})
}

// EvalCertificateMapping evaluates one expression over a certificate and returns
// a single EvaluationResult.
func (m *mapper) EvalCertificateMapping(ctx context.Context, cert traits.Mapper) (EvaluationResult, error) {
	results, err := m.eval(ctx, &varNameActivation{name: certVarName, value: cert})
	if err != nil {
		return EvaluationResult{}, err
	}
	if len(results) != 1 {
		return EvaluationResult{}, fmt.Errorf("expected 1 evaluation result, got %d", len(results))
	}
	return results[0], nil
}

// EvalCertificateMappings evaluates the given certificate expressions and returns
// a list of EvaluationResult.
func (m *mapper) EvalCertificateMappings(ctx context.Context, cert traits.Mapper) ([]EvaluationResult, error) {
	return m.eval(ctx, &varNameActivation{name: certVarName, value: cert})
}

func (m *mapper) eval(ctx context.Context, input *varNameActivation) ([]EvaluationResult, error) {
	evaluations := make([]EvaluationResult, len(m.compilationResults))

	for i, compilationResult := range m.compilationResults {
		var evaluation = &evaluations[i]
		evaluation.ExpressionAccessor = compilationResult.ExpressionAccessor

		evalResult, _, err := compilationResult.Program.ContextEval(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("expression '%s' resulted in error: %w", compilationResult.ExpressionAccessor.GetExpression(), err)
		}

		evaluation.EvalResult = evalResult
	}

	return evaluations, nil
}

var _ interpreter.Activation = &varNameActivation{}

type varNameActivation struct {
	name  string
	value traits.Mapper
}

func (v *varNameActivation) ResolveName(name string) (any, bool) {
	if v.name != name {
		return nil, false
	}
	return v.value, true
}

func (v *varNameActivation) Parent() interpreter.Activation { return nil }

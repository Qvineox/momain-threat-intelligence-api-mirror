package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/authEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgtype"
	"strings"
	"time"
)

type AuthServiceImpl struct {
	repo core.IUsersRepo

	domain string

	salt            string
	accessTokenKey  []byte
	refreshTokenKey []byte

	signingMethod *jwt.SigningMethodHMAC

	accessTokenFactory, refreshTokenFactory *authEntities.TokenFactory
}

func NewAuthServiceImpl(repo core.IUsersRepo, salt, domain string) *AuthServiceImpl {
	s := AuthServiceImpl{repo: repo, salt: salt, domain: domain, signingMethod: jwt.SigningMethodHS512}
	s.accessTokenKey = []byte("5xLJT9hThRym6u")
	s.accessTokenFactory = authEntities.NewTokenFactory(domain, "access_token", []string{"users"}, 20*time.Minute)

	s.refreshTokenKey = []byte("9WJrdq7imvMgmf")
	s.refreshTokenFactory = authEntities.NewTokenFactory(domain, "refresh_token", []string{"users"}, 48*60*time.Minute)

	return &s
}

func (s *AuthServiceImpl) GetDomain() string {
	return s.domain
}

func (s *AuthServiceImpl) ConfirmEmail(confirmationUUID pgtype.UUID) error {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) Register(login, password, fullName, email string, roleIDs []uint64) (uint64, error) {
	if len(password) == 0 || len(login) == 0 {
		return 0, errors.New("password or login empty")
	}

	if !s.isValidByPasswordPolicy(password) {
		return 0, errors.New("password not valid by policy")
	}

	newUser, err := userEntities.NewPlatformUser(fullName, login, email, s.withSalt(password), true)
	if err != nil {
		return 0, err
	}

	err = newUser.SetRoles(roleIDs)
	if err != nil {
		return 0, err
	}

	return s.repo.InsertUser(*newUser)
}

func (s *AuthServiceImpl) Login(login, password string) (accessToken, refreshToken string, err error) {
	user, err := s.repo.SelectUserByLogin(login)
	if err != nil {
		return "", "", err
	}

	if user.ID == 0 {
		return "", "", errors.New("user not found")
	}

	isValid, err := user.ComparePassword(s.withSalt(password))
	if err != nil {
		return "", "", err
	}

	if !isValid {
		return "", "", errors.New("password invalid")
	}

	accessToken, err = s.accessTokenFactory.ProduceAccessToken(user.GetRoleIDs(), user.ID).Sing(s.signingMethod, s.accessTokenKey)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.accessTokenFactory.ProduceRefreshToken().Sing(s.signingMethod, s.refreshTokenKey)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthServiceImpl) Logout(refreshToken string) error {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) Validate(accessToken string) (claims authEntities.AccessTokenClaims, err error) {
	claims, err = s.verifyToken(s.signingMethod, accessToken, s.accessTokenKey)
	if err != nil {
		return authEntities.AccessTokenClaims{}, err
	}

	return claims, err
}

func (s *AuthServiceImpl) Refresh(token string) (accessToken, refreshToken string, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) isValidByPasswordPolicy(password string) bool {
	if len(password) < 8 {
		return false
	}

	return true
}

func (s *AuthServiceImpl) withSalt(password string) string {
	return strings.Join([]string{password, s.salt}, "")
}

func (s *AuthServiceImpl) verifyToken(method *jwt.SigningMethodHMAC, tokenString string, key []byte) (authEntities.AccessTokenClaims, error) {
	var claims authEntities.AccessTokenClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{method.Alg()}))

	if token.Valid {
		return claims, nil
	}

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return claims, errors.New("token malformed")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return claims, errors.New("invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		return claims, errors.New("token expired")
	default:
		return claims, errors.New("unexpected error")
	}
}

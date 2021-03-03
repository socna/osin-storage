package osinstorage

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"fmt"

	"github.com/ansel1/merry"
	gopher_utils "github.com/felipeweb/gopher-utils"
	"github.com/gomodule/redigo/redis"
	"github.com/openshift/osin"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func init() {
	gob.Register(map[string]interface{}{})
	// gob.Register(&osin.DefaultClient{})
	gob.Register(osin.AuthorizeData{})
	gob.Register(osin.AccessData{})
}

type Storage struct {
	redis *redis.Pool
	mysql *sql.DB

	keyPrefix string
}

type StorageOption interface {
	Apply(*Storage)
}
type StorageOptionFunc func(*Storage)

func (f StorageOptionFunc) Apply(storage *Storage) {
	f(storage)
}

type RedisStore *redis.Pool

func WithRedisStore(redisStore RedisStore) StorageOption {
	return StorageOptionFunc(func(s *Storage) {
		s.redis = redisStore
	})
}

type MysqlStore *sql.DB

func WithMysqlStore(mysqlStore MysqlStore) StorageOption {
	return StorageOptionFunc(func(s *Storage) {
		s.mysql = mysqlStore
	})
}

func New(prefix string, opts ...StorageOption) *Storage {
	s := &Storage{
		keyPrefix: prefix,
	}
	for _, o := range opts {
		o.Apply(s)
	}
	return s
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
}

// GetClient loads the client by id
func (s *Storage) GetClient(id string) (osin.Client, error) {
	row := s.mysql.QueryRow(fmt.Sprintf("SELECT id, secret, redirect_uri, extra FROM %sclient WHERE id=?", s.keyPrefix), id)
	var c osin.DefaultClient
	var extra string

	if err := row.Scan(&c.Id, &c.Secret, &c.RedirectUri, &extra); err == sql.ErrNoRows {
		return nil, osin.ErrNotFound
	} else if err != nil {
		return nil, merry.Wrap(err)
	}
	c.UserData = extra
	return &c, nil
}

// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
func (s *Storage) UpdateClient(c osin.Client) error {
	data := gopher_utils.ToStr(c.GetUserData())

	if _, err := s.mysql.Exec(fmt.Sprintf("UPDATE %sclient SET secret=?, redirect_uri=?, extra=? WHERE id=?", s.keyPrefix), c.GetSecret(), c.GetRedirectUri(), data, c.GetId()); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// CreateClient stores the client in the database and returns an error, if something went wrong.
func (s *Storage) CreateClient(c osin.Client) error {
	data := gopher_utils.ToStr(c.GetUserData())

	if _, err := s.mysql.Exec(fmt.Sprintf("INSERT INTO %sclient (id, secret, redirect_uri, extra) VALUES (?, ?, ?, ?)", s.keyPrefix), c.GetId(), c.GetSecret(), c.GetRedirectUri(), data); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
func (s *Storage) RemoveClient(id string) (err error) {
	if _, err = s.mysql.Exec(fmt.Sprintf("DELETE FROM %sclient WHERE id=?", s.keyPrefix), id); err != nil {
		return merry.Wrap(err)
	}
	return nil
}

// SaveAccess creates AccessData.
func (s *Storage) SaveAccess(data *osin.AccessData) (err error) {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return err
	}

	defer conn.Close()

	payload, err := encode(data)
	if err != nil {
		return errors.Wrap(err, "failed to encode access")
	}

	accessID := uuid.NewV4().String()

	if _, err := conn.Do("SETEX", s.makeKey("access", accessID), data.ExpiresIn, string(payload)); err != nil {
		return errors.Wrap(err, "failed to save access")
	}

	if _, err := conn.Do("SETEX", s.makeKey("access_token", data.AccessToken), data.ExpiresIn, accessID); err != nil {
		return errors.Wrap(err, "failed to register access token")
	}

	_, err = conn.Do("SETEX", s.makeKey("refresh_token", data.RefreshToken), data.ExpiresIn, accessID)
	return errors.Wrap(err, "failed to register refresh token")
}

// LoadAccess gets access data with given access token
func (s *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	return s.loadAccessByKey(s.makeKey("access_token", token))
}

// RemoveAccess deletes AccessData with given access token
func (s *Storage) RemoveAccess(token string) error {
	return s.removeAccessByKey(s.makeKey("access_token", token))
}

// LoadRefresh gets access data with given refresh token
func (s *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	return s.loadAccessByKey(s.makeKey("refresh_token", token))
}

// RemoveRefresh deletes AccessData with given refresh token
func (s *Storage) RemoveRefresh(token string) error {
	return s.removeAccessByKey(s.makeKey("refresh_token", token))
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) (err error) {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return err
	}

	defer conn.Close()

	payload, err := encode(data)
	if err != nil {
		return errors.Wrap(err, "failed to encode data")
	}

	_, err = conn.Do("SETEX", s.makeKey("auth", data.Code), data.ExpiresIn, string(payload))
	return errors.Wrap(err, "failed to set auth")
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return nil, err
	}

	defer conn.Close()

	var (
		rawAuthGob interface{}
		err        error
	)

	if rawAuthGob, err = conn.Do("GET", s.makeKey("auth", code)); err != nil {
		return nil, errors.Wrap(err, "unable to GET auth")
	}
	if rawAuthGob == nil {
		return nil, nil
	}

	authGob, _ := redis.Bytes(rawAuthGob, err)

	var auth osin.AuthorizeData
	err = decode(authGob, &auth)
	return &auth, errors.Wrap(err, "failed to decode auth")
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) (err error) {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return err
	}

	defer conn.Close()

	_, err = conn.Do("DEL", s.makeKey("auth", code))
	return errors.Wrap(err, "failed to delete auth")
}

func (s *Storage) loadAccessByKey(key string) (*osin.AccessData, error) {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return nil, err
	}

	defer conn.Close()

	var (
		rawAuthGob interface{}
		err        error
	)

	if rawAuthGob, err = conn.Do("GET", key); err != nil {
		return nil, errors.Wrap(err, "unable to GET auth")
	}
	if rawAuthGob == nil {
		return nil, nil
	}

	accessID, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access ID")
	}

	accessIDKey := s.makeKey("access", accessID)
	accessGob, err := redis.Bytes(conn.Do("GET", accessIDKey))
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access gob")
	}

	var access osin.AccessData
	if err := decode(accessGob, &access); err != nil {
		return nil, errors.Wrap(err, "failed to decode access gob")
	}

	ttl, err := redis.Int(conn.Do("TTL", accessIDKey))
	if err != nil {
		return nil, errors.Wrap(err, "unable to get access TTL")
	}

	access.ExpiresIn = int32(ttl)

	access.Client, err = s.GetClient(access.Client.GetId())
	if err != nil {
		return nil, errors.Wrap(err, "unable to get client for access")
	}

	if access.AuthorizeData != nil && access.AuthorizeData.Client != nil {
		access.AuthorizeData.Client, err = s.GetClient(access.AuthorizeData.Client.GetId())
		if err != nil {
			return nil, errors.Wrap(err, "unable to get client for access authorize data")
		}
	}

	return &access, nil
}

func (s *Storage) removeAccessByKey(key string) error {
	conn := s.redis.Get()
	if err := conn.Err(); err != nil {
		return err
	}

	defer conn.Close()

	accessID, err := redis.String(conn.Do("GET", key))
	if err != nil {
		return errors.Wrap(err, "failed to get access")
	}

	access, err := s.loadAccessByKey(key)
	if err != nil {
		return errors.Wrap(err, "unable to load access for removal")
	}

	if access == nil {
		return nil
	}

	accessKey := s.makeKey("access", accessID)
	if _, err := conn.Do("DEL", accessKey); err != nil {
		return errors.Wrap(err, "failed to delete access")
	}

	accessTokenKey := s.makeKey("access_token", access.AccessToken)
	if _, err := conn.Do("DEL", accessTokenKey); err != nil {
		return errors.Wrap(err, "failed to deregister access_token")
	}

	refreshTokenKey := s.makeKey("refresh_token", access.RefreshToken)
	_, err = conn.Do("DEL", refreshTokenKey)
	return errors.Wrap(err, "failed to deregister refresh_token")
}

func (s *Storage) makeKey(namespace, id string) string {
	return fmt.Sprintf("%s:%s:%s", s.keyPrefix, namespace, id)
}

func encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, errors.Wrap(err, "unable to encode")
	}
	return buf.Bytes(), nil
}

func decode(data []byte, v interface{}) error {
	err := gob.NewDecoder(bytes.NewBuffer(data)).Decode(v)
	return errors.Wrap(err, "unable to decode")
}

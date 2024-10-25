import pytest
import json
import sqlite3
from main2 import app, createDb, insertKeyIntoDb, storeNewKey, storeExpiredKey, getValidKeysFromDb

@pytest.fixture
def client():
    """Fixture to initialize the Flask test client."""
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def setup_database():
    """Setup the database before each test."""
    createDb()  # Create a fresh database
    # Clear any existing keys from the keys table
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM keys')  # Clear existing keys
    conn.commit()
    conn.close()
    yield

def test_auth_no_keys(client):
    """Test /auth endpoint when there are no valid keys."""
    response = client.post('/auth')
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'Key not found' in data['message']

def test_auth_with_valid_key(client):
    """Test /auth endpoint when there is a valid key."""
    storeNewKey()  # Store a new key for this test
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    token = data['token']
    segments = token.split('.')
    assert len(segments) == 3  # Check if JWT has 3 segments

def test_auth_with_expired_key(client):
    """Test /auth endpoint with an expired key."""
    storeExpiredKey()  # Store an expired key for this test
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    token = data['token']
    segments = token.split('.')
    assert len(segments) == 3  # Check if JWT has 3 segments

def test_jwks(client):
    """Test the /.well-known/jwks.json endpoint."""
    storeNewKey()  # Store a new key for this test
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert len(data['keys']) > 0

    key = data['keys'][0]
    assert 'kid' in key
    assert 'kty' in key
    assert 'alg' in key
    assert 'use' in key
    assert 'n' in key
    assert 'e' in key

def test_get_valid_keys(client):
    """Test retrieval of valid keys from the database."""
    storeNewKey()
    keys = getValidKeysFromDb(expired=False)
    assert len(keys) > 0  # There should be valid keys

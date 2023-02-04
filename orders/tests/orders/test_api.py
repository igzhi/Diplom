from django.urls import reverse
import pytest
import json

from rest_framework import status
# from rest_framework.test import APIClient


def test_health(api_client):
    url = reverse('health')
    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['Status'] == 'OK'


@pytest.mark.django_db(True)
def test_user_api(api_client):
    url = reverse('register')
    response = api_client.post(url, json.dumps({
        'password': "**********",
        'email': "test.test@test.com",
        'usertype': "buyer"
    }), content_type='application/json')

    assert response.status_code == status.HTTP_200_OK
    assert response.json()['Status']

    response = api_client.post(url, json.dumps({
        'password': "**********",
        'email': "test.test@test.com",
        'usertype': "buyer"
    }), content_type='application/json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert not response.json()['Status']

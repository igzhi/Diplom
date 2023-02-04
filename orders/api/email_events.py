from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.conf import settings

from .models import User, Order

from celery.decorators import task


@task(name="on_change_order_status")
def on_change_order_status(user_id, order_id):
    """
    Отправляет пользователю с user_id письмо
    об изменении статуса заказа order_id
    """

    user = User.objects.get(id=user_id)
    order = Order.objects.get(id=order_id)

    message = 'Your order number {} have change status to "{}"'.format(
        order_id,
        order.status.upper()
    )
    to_email = user.email
    mail_subject = 'Order status changed.'
    email = EmailMessage(
                    mail_subject, message, to=[to_email]
        )
    email.send()


@task(name="on_register")
def on_register(user_id, user_mail, activation_token):
    """
    Отправляет пользователю user ссылку на эндпоинт для активаии аккаунта
    """

    id_encoded = urlsafe_base64_encode(force_bytes(user_id))
    message = 'Your Activation Link:\
        http://{}/api/v1/user/activate/{}/{}'.format(
        settings.URL_DOMAIN,
        id_encoded,
        activation_token
    )
    to_email = user_mail
    mail_subject = 'Account activation.'
    email = EmailMessage(
                    mail_subject, message, to=[to_email]
        )
    email.send()


@task(name="on_password_reset")
def on_password_reset(token_key, user_mail):
    """
    Отправляет пользователю ссылку для сброса пароля
    """

    message = "http://{}{}".format(
        settings.URL_DOMAIN,
        reverse('password_confirm', args=(token_key, )),
    )
    mail_subject = "Password Reset"
    to_email = user_mail
    email = EmailMessage(
                mail_subject, message, to=[to_email]
    )
    email.send()

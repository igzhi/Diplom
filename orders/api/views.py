from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers

from django_rest_passwordreset.signals import reset_password_token_created

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_text
from .tokens import account_activation_token
from django.contrib.auth import authenticate, login
from django.db.models import Q
from django.db.utils import IntegrityError
from django.dispatch import receiver

from .email_events import on_register, on_password_reset,\
    on_change_order_status

from drf_spectacular.utils import extend_schema, OpenApiResponse,\
    inline_serializer

from requests import get
from yaml import load, Loader

from .serializers import UserSerializer, ProductSerializer,\
    ProductModelSerializer, OrderItemSerializer, OrderSerializer,\
    ContactSerializer, CategorySerializer, ShopSerializer
from .models import User, Shop, Category, ProductModel,\
    Product, Parameter, ModelParameter, OrderItem, Order,\
    Contact


ok_data_response = OpenApiResponse(
    inline_serializer(
        name='Dict',
        fields={
            'Status': serializers.BooleanField()
        }
    )
)
error_data_response = OpenApiResponse(
    inline_serializer(
        name='Errors',
        fields={
            'Status': serializers.BooleanField(),
            'Message': serializers.CharField()
        }
    ),
    description='Returned text of exceptions in Message field'
)


# Create your views here.
def health(request):
    return JsonResponse({'Status': 'OK'}, status=200)


@extend_schema(
    request=UserSerializer,
    responses={
        200: ok_data_response,
        400: error_data_response,
    },
    auth=[{}]
)
@api_view(['POST', ])
def register_user_view(request):

    """
    View для регистрации новых пользователей в системе
    """
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():

        account = serializer.save()
        account.set_password(request.data['password'])
        account.save()

        activation_token = account_activation_token.make_token(account)
        on_register.delay(account.id, account.email, activation_token)
    else:
        return JsonResponse({'Status': False, 'Message': serializer.errors},
                            status=400)

    return JsonResponse({'Status': True})


@extend_schema(
    responses={
        200: ok_data_response,
        400: error_data_response,
    },
    auth=[{}]
)
@api_view(['GET', ])
def activate_user_view(request, uidb64, token):
    """
    View для активации аккаунтов зарегистрированных пользователей

    uid64, token -- ID и токен, отправленные пользователю на почтовый адрес
    """

    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_activated = True
        user.save()

        return JsonResponse({'Status': True})
    else:
        return JsonResponse({
            'Status': False,
            'Message': 'Activation link is invalid!'},
            status=400)


@extend_schema(
    responses={
        200: OpenApiResponse(
            inline_serializer(
                name='TokenData',
                fields={
                    'Status': serializers.BooleanField(),
                    'Token': serializers.CharField()
                }
            ),
            description='Return user auth token in "Token" field'
        ),
        400: error_data_response,
    },
    auth=[{}]
)
@api_view(['POST', ])
def login_user_view(request):

    """View для авторизации пользователей"""

    email = request.data['email']
    password = request.data['password']

    user = authenticate(request, username=email, password=password)

    if user is not None:
        login(request, user)

        token, created = Token.objects.get_or_create(user=user)
        return JsonResponse({
            'Status': True,
            'Token': token.key
        })
    else:
        return JsonResponse({
            'Status': False,
            'Message': 'Invalid login/password'
        }, status=400)


@receiver(reset_password_token_created)
def password_reset_token_created(
                sender, instance, reset_password_token, *args, **kwargs):

    """Сигнал для отправки токена сброса пароля пользователю"""

    on_password_reset.delay(
        reset_password_token.key,
        reset_password_token.user.email
    )


@api_view(['GET', ])
def reset_password_view(request, token):

    """View для отправки нового пароля пользователем"""

    return JsonResponse({
        'Status': True,
        'Message': 'Page with form for password reseting on frontend'
    })


@extend_schema(
    request=inline_serializer(
        name='SendUrlForUpdate',
        fields={
            'url': serializers.URLField()
        }
    ),
    responses={
        200: ok_data_response,
        400: error_data_response,
    },
)
@api_view(['POST', ])
def import_products_view(request):

    """View для отправки поставщиком прайс листа"""

    if not request.user.is_authenticated:
        return JsonResponse({
            'Status': False,
            'Message': 'Non authorized user'
            },
            status=400)

    if request.user.usertype != 'shop':
        return JsonResponse({
            'Status': False,
            'Message': 'Only shops can import price lists'
        }, status=400)

    if 'url' in request.data.keys():
        yaml_data = get(request.data.get('url')).content
        yaml_content = load(yaml_data, Loader=Loader)

        shop, created = Shop.objects.get_or_create(
            name=yaml_content['shop'],
            user=request.user,
            url=request.data.get('url')
        )
        for category in yaml_content['categories']:
            new_category, created = Category.objects.get_or_create(
                name=category['name'],
                id=category['id']
            )
            new_category.shops.add(shop.id)
            new_category.save()

        # Clear old products data
        ProductModel.objects.filter(shop=shop.id).delete()

        for shop_product in yaml_content['goods']:
            new_product, created = Product.objects.get_or_create(
                name=shop_product['model'],
                category_id=shop_product['category']
            )

            new_product_model = ProductModel.objects.create(
                name=shop_product['name'],
                product=new_product,
                shop=shop,
                price=shop_product['price'],
                quantity=shop_product['quantity']
            )
            for param, value in shop_product['parameters'].items():
                new_parameter, created = Parameter.objects.get_or_create(
                    name=param
                )
                ModelParameter.objects.get_or_create(
                    parameter=new_parameter,
                    product_model=new_product_model,
                    value=value
                )

        return JsonResponse({
            'Status': True
        })
    else:
        return JsonResponse({
            'Status': False,
            'Message': 'Need url adress to file'
        }, status=400)


@extend_schema(
    request=inline_serializer(
        name='ShopStatusUpdate',
        fields={
            'status': serializers.BooleanField()
        }
    ),
    responses={
        200: ok_data_response,
        400: error_data_response,
    },
    description='Available only for users with "shop" usertype'
)
@api_view(['POST', ])
def change_status_view(request):

    """View для изменения статуса поставщика"""

    if not request.user.is_authenticated:
        return JsonResponse({
            'Status': False,
            'Message': 'Non authorized user'
            },
            status=400)

    if request.user.usertype != 'shop':
        return JsonResponse({
            'Status': False,
            'Message': 'Only shops can have status'
        }, status=400)

    if 'status' in request.data.keys():
        is_updated = Shop.objects.filter(
            user=request.user.id
        ).update(
            status=request.data['status']
        )
        if is_updated:
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Message': "Update Failed"})
    else:
        return JsonResponse({
            'Status': False,
            'Message': "Field 'status' requiered"
        })


class ProductsViewSet(ReadOnlyModelViewSet):

    """View для просмотра товаров"""

    # Просмотр списка всех товаров работающих магазинов
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='ProiductList',
                    fields={
                        'Status': serializers.BooleanField(),
                        'data': ProductModelSerializer(many=True)
                    }
                )
            )
        },
        auth=[{}]
    )
    def list(self, request):
        conditions = Q(shop__status=True)

        category_id = request.data.get('category_id')
        shop_id = request.data.get('shop_id')

        if shop_id:
            conditions = conditions & Q(shop_id=shop_id)

        if category_id:
            conditions = conditions & Q(product__category_id=category_id)

        query = ProductModel.objects.filter(conditions).\
            select_related('product__category', 'shop').\
            prefetch_related('parameters__parameter')

        result = ProductModelSerializer(query.all(), many=True)
        return JsonResponse({"Status": True, "data": result.data})

    # Просмотр товара по ID
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='ProiductList',
                    fields={
                        'Status': serializers.BooleanField(),
                        'data': ProductModelSerializer()
                    }
                )
            )
        },
        auth=[{}]
    )
    def retrieve(self, request, pk=None):
        conditions = Q(shop__status=True) & Q(product__id=pk)
        query = ProductModel.objects.filter(conditions).\
            select_related('product__category', 'shop').\
            prefetch_related('parameters__parameter')

        result = ProductModelSerializer(query.all(), many=True)

        return JsonResponse({"Status": True, "data": result.data})


class BasketView(APIView):

    """Класс для работы с корзиной пользователя"""

    # Получает всю корзину
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='ProiductList',
                    fields={
                        'Status': serializers.BooleanField(),
                        'data': OrderSerializer()
                    }
                )
            ),
            400: error_data_response,
        }
    )
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({
                'Status': False,
                'Message': 'Non authorized user'
                },
                status=400)

        user_id = request.user.id

        query = Order.objects.filter(user_id=user_id, status='basket').\
            prefetch_related(
                'items__parameters__product__category',
                'items__parameters__shop',
                'items__parameters__parameters__parameter'
            )

        result = OrderSerializer(query, many=True)

        return JsonResponse({"Status": True, "data": result.data})

    # Добавляем, меняем количество товаров или удаляем товар в корзине
    @extend_schema(
        request=inline_serializer(
            name='BasketItemsList',
            fields={
                'items': inline_serializer(
                    name='ConcreteItemRequest',
                    fields={
                        'model_id': serializers.IntegerField(),
                        'quantity': serializers.IntegerField()
                    },
                    many=True
                )
            },
        ),
        responses={
            200: ok_data_response,
            400: error_data_response,
        }
    )
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({
                'Status': False,
                'Message': 'Non authorized user'
                },
                status=400)

        basket, created = Order.objects.get_or_create(
            user_id=request.user.id,
            status='basket'
        )

        items = request.data.get('items')
        if items is None:
            return JsonResponse(
                {
                    "Status": False,
                    "Message": "Wrong data format"
                },
                status=400
            )

        for item in items:
            if not {'model_id', 'quantity'}.issubset(item.keys()):
                return JsonResponse(
                    {
                        "Status": False,
                        "Message": "Wrong data format"
                    },
                    status=400
                )

            model = ProductModel.objects.filter(id=item['model_id']).get()

            ordered_item = OrderItem.objects.filter(
                parameters=model,
                order=basket).first()
            if ordered_item:
                if item['quantity'] == 0:
                    ordered_item.delete()
                else:
                    ordered_item.quantity = item['quantity']
                    ordered_item.save()
            else:
                data = {
                    'parameters': item['model_id'],
                    'order': basket.id,
                    'quantity': item['quantity']
                }

                ordered_item = OrderItemSerializer(data=data)
                if ordered_item.is_valid():
                    ordered_item.save()
                else:
                    return JsonResponse(
                        {
                            "Status": False,
                            'Message': ordered_item.errors
                        })
        return JsonResponse({"Status": True})

    # удаляем товар из корзины
    @extend_schema(
        request=inline_serializer(
            name='DeleteBasketItemsList',
            fields={
                'items': serializers.IntegerField()
            }
        ),
        responses={
            200: ok_data_response,
            400: error_data_response,
        }
    )
    def delete(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({
                'Status': False,
                'Message': 'Non authorized user'
                },
                status=400)

        basket = Order.objects.filter(
            user_id=request.user.id,
            status='basket').first()
        if not basket:
            return JsonResponse({
                'Status': False,
                'Message': 'Basket already empty'
                },
                status=400)

        items = request.data.get('items')
        if items is None:
            return JsonResponse(
                {
                    "Status": False,
                    "Message": "Wrong data format"
                },
                status=400
            )

        for item in items:
            model = ProductModel.objects.filter(id=item).first()

            ordered_item = OrderItem.objects.filter(
                parameters=model,
                order=basket).first()
            if ordered_item:
                ordered_item.delete()

        return JsonResponse({"Status": True})


@extend_schema(
    responses={
        200: ok_data_response,
        400: error_data_response,
    }
)
@api_view(['POST', ])
def order_confirmation_view(request):

    """View для подтверждения заказа и переноса его из корзины"""

    if not request.user.is_authenticated:
        return JsonResponse({
            'Status': False,
            'Message': 'Non authorized user'
            }, status=400)

    if 'contact_id' not in request.data.keys():
        return JsonResponse({'Status': False, 'Message': 'Contact ID needed'})

    filter_query = Order.objects.filter(user=request.user, status='basket')
    basket = filter_query.first()
    if basket is not None:
        saved_summ = basket.order_sum
        if saved_summ == 0:
            return JsonResponse({
                'Status': False,
                'Message': 'Basket is empty'
            })

        try:
            is_updated = filter_query.update(
                saved_sum=saved_summ,
                contact=request.data['contact_id'],
                status='new'
            )
        except IntegrityError:
            return JsonResponse({
                'Status': False,
                'Message': 'Error of sended data'
                })

        if is_updated:
            on_change_order_status.delay(request.user.id, basket.id)
            return JsonResponse({'Status': True})
        else:
            error_message = 'Update failed'
    else:
        error_message = 'Basket is empty'

    return JsonResponse({'Status': False, 'Message': error_message})


@extend_schema(
    responses={
        200: OrderSerializer(many=True),
        400: error_data_response,
    },
    description='Get List of orders with products from logged in shop user'
)
@api_view(['GET', ])
def shop_orders_view(request):

    """View для просмотра заказов для поставщика"""

    if not request.user.is_authenticated:
        return JsonResponse({
            'Status': False,
            'Message': 'Non authorized user'
            },
            status=400)

    if request.user.usertype != 'shop':
        return JsonResponse({
            'Status': False,
            'Message': 'Only shops can see his orders'
        }, status=400)

    orders = Order.objects.filter(
        items__parameters__shop__user=request.user.id
    ).exclude(
        status='basket'
    ).prefetch_related(
        'items__parameters__shop__user',
        'items__parameters__product',
        'items__parameters__parameters__parameter'
    ).select_related(
        'contact',
        'user'
    ).all()
    serializer = OrderSerializer(orders, many=True)
    return JsonResponse({
            'Status': True,
            'Data': serializer.data
        })


class ContactsViewSet(ModelViewSet):

    """Класс для работы с контактами пользователя"""

    permission_classes = [IsAuthenticated]
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer

    # Получаем список контактов пользователя
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='CreateContactResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': ContactSerializer(many=True)
                    }
                )
            ),
            400: error_data_response,
        },
        description='Get List of users contacts'
    )
    def list(self, request):
        queryset = self.queryset.filter(user_id=request.user.id)
        serializer = ContactSerializer(queryset, many=True)

        return JsonResponse({'Status': True, 'Data': serializer.data})

    # Добавляем новый контакт
    @extend_schema(
        request=ContactSerializer,
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='CreateContactResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': ContactSerializer
                    }
                )
            ),
            400: error_data_response,
        },
        description='Add new contact for user'
    )
    def create(self, request):
        request.data['user'] = request.user.id
        contact = self.serializer_class(data=request.data)
        if contact.is_valid():
            contact.save()
            return JsonResponse(
                {
                    "Status": True,
                    "data": contact.data
                }
            )
        else:
            return JsonResponse(
                {
                    "Status": False,
                    "Message": contact.errors
                }
            )

    # Удаляем один из контактов
    @extend_schema(
        responses={
            200: ok_data_response,
            400: error_data_response,
        },
        description='Add new contact for user'
    )
    def destroy(self, request, pk=None):
        contact = self.queryset.filter(user=request.user, id=pk).first()
        if contact:
            contact.delete()
            return JsonResponse({"Status": True})
        else:
            return JsonResponse(
                {
                    "Status": False,
                    "Message": "Contact not found"
                }
            )

    # Обновление полей контакта методом PATCH
    @extend_schema(
        request=ContactSerializer,
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='CreateContactResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': ContactSerializer
                    }
                )
            ),
            400: error_data_response,
        },
        description='Add new contact for user'
    )
    def partial_update(self, request, pk=None):
        contact = self.queryset.filter(user=request.user, id=pk).first()
        if contact:
            serializer = ContactSerializer(
                contact,
                data=request.data,
                partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(
                    {
                        "Status": True,
                        "data": serializer.data
                    }
                )
            else:
                return JsonResponse(
                    {
                        "Status": False,
                        "Message": serializer.errors
                    }
                )

        else:
            return JsonResponse(
                {
                    "Status": False,
                    "Message": "Contact not found"
                }
            )

    # Обновление полей контакта методом PUT
    @extend_schema(
        request=ContactSerializer,
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='CreateContactResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': ContactSerializer
                    }
                )
            ),
            400: error_data_response,
        },
        description='Add new contact for user'
    )
    def update(self, request, pk=None):
        return self.partial_update(request, pk)


class OrderViewSet(ReadOnlyModelViewSet):

    """Класс для работы с заказами, сделанными пользователем"""

    permission_classes = [IsAuthenticated]

    queryset = Order.objects.all()
    serializer_class = OrderSerializer

    # Получаем список заказов пользователя
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='ListOrdersResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': OrderSerializer(many=True)
                    }
                )
            ),
            400: error_data_response,
        }
    )
    def list(self, request):
        queryset = self.queryset.filter(user_id=request.user.id).exclude(
            status='basket'
        )
        serializer = self.serializer_class(queryset, many=True)

        return JsonResponse({
            'Status': True,
            'data': serializer.data
        })

    # Получение заказа по ID
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='ListOrdersResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': OrderSerializer
                    }
                )
            ),
            400: error_data_response,
        }
    )
    def retrieve(self, request, pk=None):
        orders = self.queryset.filter(user_id=request.user.id, id=pk).exclude(
            status='basket'
        )
        serializer = OrderSerializer(orders, many=True)

        return JsonResponse({
            'Status': True,
            'data': serializer.data
        })


class UserView(APIView):

    """Класс для работы с данными пользователей"""

    # Получить данные текущего пользователя
    @extend_schema(
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='UserDataResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': UserSerializer
                    }
                )
            ),
            400: error_data_response,
        }
    )
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({
                'Status': False,
                'Message': 'Non authorized user'
                },
                status=400)

        serializer = UserSerializer(request.user)
        return JsonResponse({
            'Status': True,
            'data': serializer.data
        })

    # Изменяем данные пользователя
    @extend_schema(
        request=UserSerializer,
        responses={
            200: OpenApiResponse(
                inline_serializer(
                    name='UserDataResponse',
                    fields={
                        'Status': serializers.BooleanField(),
                        'Data': UserSerializer
                    }
                )
            ),
            400: error_data_response,
        }
    )
    def put(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({
                'Status': False,
                'Message': 'Non authorized user'
                },
                status=400)

        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return JsonResponse({
                'Status': True,
                'data': serializer.data
            })
        else:
            return JsonResponse({
                'Status': False,
                'Message': serializer.errors
            })


class CategoryView(ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ProductView(ListAPIView):

    """Класс для просмотра категорий"""

    queryset = Product.objects.all()
    serializer_class = ProductSerializer


class ShopView(ListAPIView):

    """Класс для просмотра списка магазинов"""

    queryset = Shop.objects.all()
    serializer_class = ShopSerializer

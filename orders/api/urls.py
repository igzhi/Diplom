from django.urls import path, include
from django.conf.urls import url
from rest_framework.routers import DefaultRouter

from .views import register_user_view, activate_user_view,\
    login_user_view, import_products_view, change_status_view,\
    shop_orders_view, ProductsViewSet, BasketView,\
    order_confirmation_view, ContactsViewSet, reset_password_view,\
    OrderViewSet, UserView, CategoryView, ShopView, health

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

router = DefaultRouter()
router.register(r'api/v1/product', ProductsViewSet, basename='product')
router.register(r'api/v1/contacts', ContactsViewSet, basename='contacts')
router.register(r'api/v1/orders', OrderViewSet, basename='orders')

urlpatterns = [
    path('health', health, name='health'),
    path('api/v1/user/login/', login_user_view, name='login'),
    path('api/v1/user/register/', register_user_view, name='register'),
    path('api/v1/user/password_reset/', include(
        'django_rest_passwordreset.urls', namespace='password_reset'
    )),
    url('api/v1/user/activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        activate_user_view, name='activate'),
    path(
        'api/v1/user/passwordreset_confirm/<str:token>/',
        reset_password_view,
        name='password_confirm'),
    path('api/v1/user/', UserView.as_view(), name='user'),

    path('api/v1/shop/import/', import_products_view, name='shop_import'),
    path('api/v1/shop/stauts/', change_status_view, name='shop_status'),
    path('api/v1/shop/orders/', shop_orders_view, name='shop_orders'),

    path('api/v1/basket/', BasketView.as_view(), name='basket'),
    path('api/v1/confirmation/', order_confirmation_view, name='confirmation'),
    path('api/v1/category/', CategoryView.as_view(), name='category'),
    path('api/v1/shops/', ShopView.as_view(), name='shops'),

    path('', include(router.urls)),

    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "docs/",
        SpectacularSwaggerView.as_view(
            url_name="schema"
        ),
        name="swagger-ui",
    ),
]

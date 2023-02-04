from rest_framework import serializers
from .models import User, Shop, Category, Product, ProductModel,\
    Parameter, ModelParameter, Order, OrderItem, Contact


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'password', 'username', 'email',
                        'usertype', 'first_name', 'last_name']
        extra_kwargs = {
            'password': {'write_only': True},
        }
        read_only_fields = ['id', ]


class ShopSerializer(serializers.ModelSerializer):

    class Meta:
        model = Shop
        fields = ['name', 'status']


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ['name']


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ['name', 'category']


class ParameterSerializer(serializers.ModelSerializer):

    class Meta:
        model = Parameter
        fields = ['name']


class ModelParameterSerializer(serializers.ModelSerializer):

    parameter = serializers.StringRelatedField()

    class Meta:
        model = ModelParameter
        fields = ['parameter', 'value']


class ProductModelSerializer(serializers.ModelSerializer):

    product = ProductSerializer()
    shop = serializers.StringRelatedField()
    parameters = ModelParameterSerializer(many=True)

    class Meta:
        model = ProductModel
        fields = ['id', 'name', 'price', 'quantity',
                        'product', 'shop', 'parameters']
        read_only_fields = ['id']


class OrderItemSerializer(serializers.ModelSerializer):

    # parameters = ProductModelSerializer()
    # order = serializers.StringRelatedField()

    class Meta:
        model = OrderItem
        fields = ['parameters', 'quantity', 'order']


class OrderItemGetSerializer(serializers.ModelSerializer):
    parameters = ProductModelSerializer()

    class Meta:
        model = OrderItem
        fields = ['parameters', 'quantity', 'order']


class ContactSerializer(serializers.ModelSerializer):

    class Meta:
        model = Contact
        fields = ['id', 'city', 'street', 'house',
                        'apartment', 'phone_number', 'user']
        read_only_fields = ['id']


class OrderSerializer(serializers.ModelSerializer):

    user = serializers.StringRelatedField()
    items = OrderItemGetSerializer(many=True)
    contact = ContactSerializer()

    class Meta:
        model = Order
        fields = ['id', 'user', 'status', 'items', 'order_sum', 'contact']
        read_only_fields = ['id']

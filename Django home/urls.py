from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("create-checkout-session/", views.create_checkout_session, name="create_checkout_session"),
    path("order/success/", views.order_success, name="order_success"),
    path("order/cancel/", views.order_cancel, name="order_cancel"),
]

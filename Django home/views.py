import json
import stripe
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

stripe.api_key = settings.STRIPE_SECRET_KEY

# Server-side price list — NEVER trust prices sent from the browser.
# Keep this in sync with the DISHES array in home.html (id, name, price in dollars).
DISHES = {
    "af1": {"name": "Jollof Rice & Grilled Chicken", "price": 14.50},
    "af2": {"name": "Suya Beef Skewers", "price": 12.00},
    "af3": {"name": "Injera with Doro Wat", "price": 15.00},
    "af4": {"name": "Chin Chin", "price": 5.50},
    "af5": {"name": "Bissap Hibiscus Cooler", "price": 4.00},
    "as1": {"name": "Pad Thai", "price": 13.50},
    "as2": {"name": "Sushi Sampler Platter", "price": 18.00},
    "as3": {"name": "Shoyu Ramen", "price": 14.00},
    "as4": {"name": "Mango Sticky Rice", "price": 6.50},
    "as5": {"name": "Thai Iced Tea", "price": 4.50},
    "mx1": {"name": "Tacos al Pastor (3pc)", "price": 11.50},
    "mx2": {"name": "Street Corn Elote", "price": 6.00},
    "mx3": {"name": "Chiles Rellenos", "price": 13.00},
    "mx4": {"name": "Churros & Chocolate", "price": 6.50},
    "mx5": {"name": "Horchata", "price": 4.00},
    "fi1": {"name": "Karjalanpiirakka", "price": 9.00},
    "fi2": {"name": "Lohikeitto Salmon Soup", "price": 14.50},
    "fi3": {"name": "Sautéed Reindeer", "price": 19.00},
    "fi4": {"name": "Cinnamon Pulla", "price": 4.50},
    "fi5": {"name": "Glögi Mulled Berry Drink", "price": 5.00},
    "fr1": {"name": "Coq au Vin", "price": 17.50},
    "fr2": {"name": "French Onion Soup", "price": 9.50},
    "fr3": {"name": "Ratatouille", "price": 12.00},
    "fr4": {"name": "Crème Brûlée", "price": 7.00},
    "fr5": {"name": "Vin Chaud", "price": 5.50},
}

DELIVERY_FEE = 3.50


def home(request):
    return render(request, "menu/home.html")


@require_POST
def create_checkout_session(request):
    """
    Called by fetch() from home.html. Expects JSON: {"cart": {"af1": 2, "mx3": 1, ...}}
    Builds Stripe line items from the server-side DISHES dict (so prices can't be
    tampered with in the browser), creates a Checkout Session, and returns its URL.
    """
    try:
        data = json.loads(request.body)
        cart = data.get("cart", {})
        if not cart:
            return JsonResponse({"error": "Basket is empty."}, status=400)

        line_items = []
        for dish_id, qty in cart.items():
            dish = DISHES.get(dish_id)
            if not dish or not isinstance(qty, int) or qty <= 0:
                continue
            line_items.append({
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": dish["name"]},
                    "unit_amount": round(dish["price"] * 100),  # Stripe uses cents
                },
                "quantity": qty,
            })

        if not line_items:
            return JsonResponse({"error": "No valid items in basket."}, status=400)

        # Delivery fee as its own line item
        line_items.append({
            "price_data": {
                "currency": "usd",
                "product_data": {"name": "Delivery"},
                "unit_amount": round(DELIVERY_FEE * 100),
            },
            "quantity": 1,
        })

        session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=line_items,
            success_url=request.build_absolute_uri("/order/success/") + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=request.build_absolute_uri("/order/cancel/"),
        )
        return JsonResponse({"url": session.url})

    except (json.JSONDecodeError, KeyError):
        return JsonResponse({"error": "Invalid request."}, status=400)
    except stripe.error.StripeError as e:
        return JsonResponse({"error": str(e)}, status=400)


def order_success(request):
    session_id = request.GET.get("session_id")
    session = None
    if session_id:
        try:
            session = stripe.checkout.Session.retrieve(session_id)
        except stripe.error.StripeError:
            pass
    return render(request, "menu/success.html", {"session": session})


def order_cancel(request):
    return render(request, "menu/cancel.html")

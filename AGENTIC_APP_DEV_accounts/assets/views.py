from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from accounts.permissions import CAN_EDIT_ASSETS, RoleRequiredMixin
from assets.forms import CloudAssetForm
from assets.models import CloudAsset


class AssetListView(RoleRequiredMixin, ListView):
    model = CloudAsset
    template_name = "assets/asset_list.html"
    context_object_name = "assets"
    paginate_by = 25
    allowed_roles = ("admin", "analyst", "auditor")

    def get_queryset(self):
        qs = CloudAsset.objects.select_related("owner").all()
        provider = self.request.GET.get("provider")
        q = self.request.GET.get("q")
        if provider:
            qs = qs.filter(provider=provider)
        if q:
            qs = qs.filter(name__icontains=q)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["selected_provider"] = self.request.GET.get("provider", "")
        ctx["query"] = self.request.GET.get("q", "")
        return ctx


class AssetDetailView(RoleRequiredMixin, DetailView):
    model = CloudAsset
    template_name = "assets/asset_detail.html"
    context_object_name = "asset"
    allowed_roles = ("admin", "analyst", "auditor")

    def get_queryset(self):
        return CloudAsset.objects.select_related("owner").prefetch_related("vulnerabilities", "compliance_records")


class AssetCreateView(RoleRequiredMixin, CreateView):
    model = CloudAsset
    form_class = CloudAssetForm
    template_name = "assets/asset_form.html"
    success_url = reverse_lazy("assets:list")
    allowed_roles = CAN_EDIT_ASSETS

    def form_valid(self, form):
        messages.success(self.request, "Cloud asset added to the inventory.")
        return super().form_valid(form)


class AssetUpdateView(RoleRequiredMixin, UpdateView):
    model = CloudAsset
    form_class = CloudAssetForm
    template_name = "assets/asset_form.html"
    success_url = reverse_lazy("assets:list")
    allowed_roles = CAN_EDIT_ASSETS

    def form_valid(self, form):
        messages.success(self.request, "Cloud asset updated.")
        return super().form_valid(form)


class AssetDeleteView(RoleRequiredMixin, DeleteView):
    model = CloudAsset
    template_name = "assets/asset_confirm_delete.html"
    success_url = reverse_lazy("assets:list")
    allowed_roles = CAN_EDIT_ASSETS

    def form_valid(self, form):
        messages.success(self.request, "Cloud asset removed from the inventory.")
        return super().form_valid(form)

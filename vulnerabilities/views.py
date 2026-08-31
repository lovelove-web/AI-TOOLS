from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from accounts.permissions import CAN_EDIT_VULNERABILITIES, RoleRequiredMixin
from vulnerabilities.forms import VulnerabilityForm
from vulnerabilities.models import Vulnerability


class VulnerabilityListView(RoleRequiredMixin, ListView):
    model = Vulnerability
    template_name = "vulnerabilities/vulnerability_list.html"
    context_object_name = "vulnerabilities"
    paginate_by = 25
    allowed_roles = ("admin", "analyst", "auditor")

    def get_queryset(self):
        qs = Vulnerability.objects.select_related("asset", "assigned_to").all()
        severity = self.request.GET.get("severity")
        status = self.request.GET.get("status")
        provider = self.request.GET.get("provider")
        if severity:
            qs = qs.filter(severity=severity)
        if status:
            qs = qs.filter(status=status)
        if provider:
            qs = qs.filter(asset__provider=provider)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx.update({
            "selected_severity": self.request.GET.get("severity", ""),
            "selected_status": self.request.GET.get("status", ""),
            "selected_provider": self.request.GET.get("provider", ""),
        })
        return ctx


class VulnerabilityDetailView(RoleRequiredMixin, DetailView):
    model = Vulnerability
    template_name = "vulnerabilities/vulnerability_detail.html"
    context_object_name = "vulnerability"
    allowed_roles = ("admin", "analyst", "auditor")


class VulnerabilityCreateView(RoleRequiredMixin, CreateView):
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = "vulnerabilities/vulnerability_form.html"
    success_url = reverse_lazy("vulnerabilities:list")
    allowed_roles = CAN_EDIT_VULNERABILITIES

    def form_valid(self, form):
        messages.success(self.request, "Vulnerability recorded and ready for triage.")
        return super().form_valid(form)


class VulnerabilityUpdateView(RoleRequiredMixin, UpdateView):
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = "vulnerabilities/vulnerability_form.html"
    success_url = reverse_lazy("vulnerabilities:list")
    allowed_roles = CAN_EDIT_VULNERABILITIES

    def form_valid(self, form):
        messages.success(self.request, "Vulnerability updated.")
        return super().form_valid(form)


class VulnerabilityDeleteView(RoleRequiredMixin, DeleteView):
    model = Vulnerability
    template_name = "vulnerabilities/vulnerability_confirm_delete.html"
    success_url = reverse_lazy("vulnerabilities:list")
    allowed_roles = CAN_EDIT_VULNERABILITIES

    def form_valid(self, form):
        messages.success(self.request, "Vulnerability deleted.")
        return super().form_valid(form)

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from accounts.permissions import CAN_EDIT_COMPLIANCE, CAN_VIEW_COMPLIANCE, RoleRequiredMixin
from compliance.forms import ComplianceRecordForm, EvidenceForm
from compliance.models import ComplianceRecord, ComplianceStatus, Framework


class ComplianceRecordListView(RoleRequiredMixin, ListView):
    model = ComplianceRecord
    template_name = "compliance/record_list.html"
    context_object_name = "records"
    paginate_by = 25
    allowed_roles = CAN_VIEW_COMPLIANCE

    def get_queryset(self):
        qs = ComplianceRecord.objects.select_related("control", "control__framework", "asset", "owner")
        framework = self.request.GET.get("framework")
        status = self.request.GET.get("status")
        if framework:
            qs = qs.filter(control__framework_id=framework)
        if status:
            qs = qs.filter(status=status)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["frameworks"] = Framework.objects.all()
        ctx["selected_framework"] = self.request.GET.get("framework", "")
        ctx["selected_status"] = self.request.GET.get("status", "")
        return ctx


class ComplianceRecordDetailView(RoleRequiredMixin, DetailView):
    model = ComplianceRecord
    template_name = "compliance/record_detail.html"
    context_object_name = "record"
    allowed_roles = CAN_VIEW_COMPLIANCE

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["evidence_form"] = EvidenceForm()
        return ctx


class ComplianceRecordCreateView(RoleRequiredMixin, CreateView):
    model = ComplianceRecord
    form_class = ComplianceRecordForm
    template_name = "compliance/record_form.html"
    success_url = reverse_lazy("compliance:list")
    allowed_roles = CAN_EDIT_COMPLIANCE

    def form_valid(self, form):
        if not form.instance.owner:
            form.instance.owner = self.request.user
        messages.success(self.request, "Compliance record created.")
        return super().form_valid(form)


class ComplianceRecordUpdateView(RoleRequiredMixin, UpdateView):
    model = ComplianceRecord
    form_class = ComplianceRecordForm
    template_name = "compliance/record_form.html"
    success_url = reverse_lazy("compliance:list")
    allowed_roles = CAN_EDIT_COMPLIANCE

    def form_valid(self, form):
        messages.success(self.request, "Compliance record updated.")
        return super().form_valid(form)


class ComplianceRecordDeleteView(RoleRequiredMixin, DeleteView):
    model = ComplianceRecord
    template_name = "compliance/record_confirm_delete.html"
    success_url = reverse_lazy("compliance:list")
    allowed_roles = CAN_EDIT_COMPLIANCE

    def form_valid(self, form):
        messages.success(self.request, "Compliance record deleted.")
        return super().form_valid(form)


class UploadEvidenceView(RoleRequiredMixin, CreateView):
    """Attach an evidence file to a compliance record (Admin/Analyst only)."""

    form_class = EvidenceForm
    allowed_roles = CAN_EDIT_COMPLIANCE

    def post(self, request, *args, **kwargs):
        record = get_object_or_404(ComplianceRecord, pk=kwargs["pk"])
        form = EvidenceForm(request.POST, request.FILES)
        if form.is_valid():
            evidence = form.save(commit=False)
            evidence.compliance_record = record
            evidence.uploaded_by = request.user
            evidence.save()
            messages.success(request, "Evidence uploaded.")
        else:
            messages.error(request, f"Could not upload evidence: {form.errors.as_text()}")
        return redirect("compliance:detail", pk=record.pk)


class AuditPrepView(RoleRequiredMixin, ListView):
    """Dashboard highlighting non-compliant records and overdue reviews for auditors."""

    model = ComplianceRecord
    template_name = "compliance/audit_prep.html"
    context_object_name = "gap_records"
    allowed_roles = CAN_VIEW_COMPLIANCE

    def get_queryset(self):
        return (
            ComplianceRecord.objects.select_related("control", "control__framework", "asset")
            .filter(status__in=[ComplianceStatus.NON_COMPLIANT, ComplianceStatus.IN_PROGRESS])
            .order_by("control__framework", "control__code")
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["overdue_reviews"] = ComplianceRecord.objects.filter(
            next_review_due__lt=timezone.localdate()
        ).select_related("control", "control__framework")
        return ctx

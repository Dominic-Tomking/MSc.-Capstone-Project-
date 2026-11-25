from django.contrib import admin

from .models import (AggregatedFinding, Contract, Finding, Label,
                     MetricRecord, Scan, ValidationRecord)

for m in (Contract, Scan, Finding, Label, AggregatedFinding,
          ValidationRecord, MetricRecord):
    admin.site.register(m)

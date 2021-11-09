from django_filters.rest_framework import FilterSet
import django_filters
from .models import User
from django_filters.widgets import RangeWidget


class UserFilter(FilterSet):
    date_range = django_filters.DateFromToRangeFilter(label='Date Range', field_name='created_at',
                                                      widget=RangeWidget(attrs={'type': 'date'}))

    class Meta:
        model = User
        fields = ['created_at']
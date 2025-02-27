from django.contrib import admin
# Add AssetMovement import
from .models import Employee, Module, Department, Asset, AssetMovement, Role


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ['employee_number', 'name',
                    'surname', 'department', 'email', 'phone_number']
    search_fields = ['employee_number', 'name', 'surname', 'email']
    list_filter = ['department', 'branch', 'section']


@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'order']
    list_editable = ['order']


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['code', 'name', 'description']
    list_editable = ['is_active']


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ['asset_number', 'serial_number', 'name', 'category',
                    'department', 'condition', 'is_active']
    list_filter = ['category', 'department', 'condition', 'is_active']
    search_fields = ['asset_number', 'serial_number', 'name', 'description']
    list_editable = ['condition', 'is_active']


@admin.register(AssetMovement)
class AssetMovementAdmin(admin.ModelAdmin):
    list_display = ['asset', 'movement_type', 'from_location',
                    'to_location', 'status', 'stage', 'initiator', 'created_at']
    list_filter = ['movement_type', 'status', 'stage']
    search_fields = ['asset__name', 'asset__asset_number',
                     'from_location', 'to_location', 'reason']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name', 'description']

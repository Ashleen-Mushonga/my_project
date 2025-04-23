from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
# Update imports to include Role
from .models import Employee, Module, Department, Asset, AssetMovement, Role, AssetMaintenance
from django.http import HttpResponse, JsonResponse
from django.db import IntegrityError
from django.utils import timezone
import random
from datetime import datetime
import csv


def login(request):
    if request.method == 'POST':
        employee_number = request.POST.get('employee_number')
        password = request.POST.get('password')

        try:
            employee = Employee.objects.get(employee_number=employee_number)
            if check_password(password, employee.password):
                request.session['employee_id'] = employee.id

                if employee.is_first_login:
                    return redirect('reset_password')
                # Create this view for main application page
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid credentials')
        except Employee.DoesNotExist:
            messages.error(request, 'Invalid credentials')

    return render(request, 'myapp/login.html')


def logout(request):
    if 'employee_id' in request.session:
        del request.session['employee_id']
    return redirect('login')


def forgot_password(request):
    if request.method == 'POST':
        employee_number = request.POST.get('employee_number')
        try:
            employee = Employee.objects.get(employee_number=employee_number)
            # Generate a temporary password
            temp_password = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
            employee.password = make_password(temp_password)
            employee.is_first_login = True
            employee.save()

            # Here you would typically send the temporary password via email
            # For now, we'll just show it in a message
            messages.success(
                request, f'Your temporary password is: {temp_password}. Please change it after logging in.')
            return redirect('login')
        except Employee.DoesNotExist:
            messages.error(request, 'Employee number not found')

    return render(request, 'myapp/forgot_password.html')


def reset_password(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password == confirm_password:
            employee = Employee.objects.get(id=request.session['employee_id'])
            employee.password = make_password(new_password)
            employee.is_first_login = False
            employee.save()
            messages.success(request, 'Password updated successfully')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')

    return render(request, 'myapp/reset_password.html')


def dashboard(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    modules = Module.objects.all()
    return render(request, 'myapp/dashboard.html', {
        'employee': employee,
        'modules': modules
    })


def system_management_home(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])

    # Get real-time statistics
    context = {
        'employee': employee,
        'employees': {
            'count': Employee.objects.filter(is_active=True).count()
        },
        'departments': {
            'count': Department.objects.filter(is_active=True).count()
        },
        'roles': {
            'count': Role.objects.filter(is_active=True).count()
        },
        'assets': {
            'count': Asset.objects.filter(is_deleted=False).count()
        }
    }

    return render(request, 'myapp/system_management_home.html', context)


def employee_management(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    return render(request, 'myapp/employee_management.html', {
        'employee': employee,
        'employees': Employee.objects.all().order_by('-is_active', 'surname', 'name'),
        'departments': Department.objects.filter(is_active=True),
    })


def department_management(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    return render(request, 'myapp/department_management.html', {
        'employee': employee,
        'departments': Department.objects.all().order_by('-is_active', 'name'),
    })


def system_management(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    return render(request, 'myapp/system_management.html', {
        'employee': employee,
        'employees': Employee.objects.all().order_by('-is_active', 'surname', 'name'),
        'departments': Department.objects.all(),  # Just pass all departments
    })


def add_employee(request):
    if request.method == 'POST':
        try:
            employee = Employee.objects.create(
                employee_number=request.POST.get('employee_number'),
                name=request.POST.get('name'),
                surname=request.POST.get('surname'),
                email=request.POST.get('email'),
                phone_number=request.POST.get('phone_number'),
                department=request.POST.get('department'),
                branch=request.POST.get('branch'),
                section=request.POST.get('section'),
                is_first_login=True
            )
            messages.success(request, 'Employee added successfully')
        except IntegrityError as e:
            if 'phone_number' in str(e):
                messages.error(
                    request, 'This phone number is already registered')
            elif 'email' in str(e):
                messages.error(request, 'This email is already registered')
            elif 'employee_number' in str(e):
                messages.error(
                    request, 'This employee number is already registered')
            else:
                messages.error(request, f'Database error: {str(e)}')
        except Exception as e:
            messages.error(request, f'Error creating employee: {str(e)}')

    return redirect('system_management')


def edit_employee(request, employee_id):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=employee_id)
            employee.name = request.POST.get('name')
            employee.surname = request.POST.get('surname')
            employee.email = request.POST.get('email')
            employee.phone_number = request.POST.get('phone_number')
            employee.department = request.POST.get('department')
            employee.branch = request.POST.get('branch')
            employee.section = request.POST.get('section')
            employee.save()
            messages.success(request, 'Employee updated successfully')
        except IntegrityError as e:
            messages.error(
                request, 'Error updating employee: Duplicate information found')
        except Exception as e:
            messages.error(request, f'Error updating employee: {str(e)}')
    return redirect('system_management')


def toggle_employee_status(request, employee_id):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=employee_id)
            employee.is_active = not employee.is_active
            employee.save()
            status = 'activated' if employee.is_active else 'deactivated'
            messages.success(request, f'Employee {status} successfully')
            return JsonResponse({'status': 'success', 'is_active': employee.is_active})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def add_department(request):
    if request.method == 'POST':
        try:
            department = Department.objects.create(
                code=request.POST.get('code'),
                name=request.POST.get('name'),
                description=request.POST.get('description', '')
            )
            messages.success(request, 'Department added successfully')
        except IntegrityError:
            messages.error(request, 'Department code already exists')
        except Exception as e:
            messages.error(request, f'Error creating department: {str(e)}')
    return redirect('system_management')


def toggle_department_status(request, department_id):
    if request.method == 'POST':
        try:
            department = get_object_or_404(Department, id=department_id)
            department.is_active = not department.is_active
            department.save()
            status = 'activated' if department.is_active else 'deactivated'
            return JsonResponse({'status': 'success', 'is_active': department.is_active})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def asset_management(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    return render(request, 'myapp/asset_management.html', {
        'employee': employee,
        'assets': Asset.objects.all().order_by('-is_active', 'name'),
        'departments': Department.objects.filter(is_active=True),
    })


def add_asset(request):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=request.session['employee_id'])
            asset = Asset.objects.create(
                asset_number=request.POST.get('asset_number'),
                serial_number=request.POST.get('serial_number'),
                name=request.POST.get('name'),
                category=request.POST.get('category'),
                description=request.POST.get('description', ''),
                department_id=request.POST.get('department'),
                location=request.POST.get('location'),
                purchase_date=request.POST.get('purchase_date'),
                purchase_cost=request.POST.get('purchase_cost'),
                condition=request.POST.get('condition'),
                initiator=employee  # Add initiator
            )
            messages.success(request, 'Asset added successfully')
        except IntegrityError:
            messages.error(request, 'Asset number already exists')
        except Exception as e:
            messages.error(request, f'Error creating asset: {str(e)}')
    return redirect('asset_management')


def edit_asset(request, asset_id):
    if request.method == 'POST':
        try:
            asset = get_object_or_404(Asset, id=asset_id)

            # Update asset fields
            asset.asset_number = request.POST.get('asset_number')
            asset.serial_number = request.POST.get('serial_number')
            asset.name = request.POST.get('name')
            asset.category = request.POST.get('category')
            asset.department_id = request.POST.get('department')
            asset.condition = request.POST.get('condition')
            asset.location = request.POST.get('location')
            asset.is_active = request.POST.get('is_active') == 'true'

            try:
                asset.save()
                return JsonResponse({'status': 'success', 'message': 'Asset updated successfully'})
            except IntegrityError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Asset number already exists'
                }, status=400)
            except Exception as e:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Error saving asset: {str(e)}'
                }, status=400)

        except Asset.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Asset not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error updating asset: {str(e)}'
            }, status=400)
    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)


def toggle_asset_status(request, asset_id):
    if request.method == 'POST':
        try:
            asset = Asset.objects.get(id=asset_id)
            asset.is_active = not asset.is_active
            asset.save()
            return JsonResponse({'status': 'success', 'is_active': asset.is_active})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def delete_asset(request, asset_id):
    if request.method == 'POST':
        try:
            asset = get_object_or_404(Asset, id=asset_id)
            employee = Employee.objects.get(id=request.session['employee_id'])
            asset.soft_delete(employee)
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def asset_register(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])

    # Get assets with additional filtering and ordering
    assets = Asset.objects.select_related('department', 'initiator').filter(
        is_deleted=False
    ).order_by('-created_at')

    # Get stats for dashboard
    stats = {
        'total_assets': assets.count(),
        'active_assets': assets.filter(is_active=True).count(),
        'retired_assets': assets.filter(condition='RETIRED').count(),
        'total_value': sum(asset.purchase_cost for asset in assets),
    }

    return render(request, 'myapp/asset_register.html', {
        'employee': employee,
        'assets': assets,
        'stats': stats,
        'departments': Department.objects.filter(is_active=True),
    })


def asset_movement(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    context = {
        'employee': employee,
        'movements': AssetMovement.objects.all().order_by('-created_at'),
        'assets': Asset.objects.filter(is_active=True)
    }
    return render(request, 'myapp/asset_movement.html', context)


def create_movement(request):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=request.session['employee_id'])
            movement = AssetMovement.objects.create(
                asset_id=request.POST.get('asset'),
                movement_type=request.POST.get('movement_type'),
                from_location=request.POST.get('from_location'),
                to_location=request.POST.get('to_location'),
                reason=request.POST.get('reason'),
                initiator=employee
            )

            # Handle file upload
            if 'attachment' in request.FILES:
                movement.attachment = request.FILES['attachment']
                movement.save()

            messages.success(request, 'Movement request created successfully')
        except Exception as e:
            messages.error(
                request, f'Error creating movement request: {str(e)}')
    return redirect('asset_movement')


def can_approve_movements(employee):
    """Check if employee has permission to approve movements"""
    for role in employee.roles.all():
        permissions = role.permissions
        if 'Movement' in permissions and 'approve' in permissions['Movement']:
            return True
    return False


def approve_movement(request, movement_id):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=request.session['employee_id'])

            # Check if employee has approve permission
            if not can_approve_movements(employee):
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to approve movements'
                }, status=403)

            # Get the movement
            movement = AssetMovement.objects.get(id=movement_id)

            # Check if the approver is the same person who initiated the request
            if movement.initiator == employee:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot approve movements you initiated'
                }, status=403)

            # Process the approval
            movement.status = 'APPROVED'
            movement.stage = 'IN_PROGRESS'
            movement.approver = employee
            movement.approval_date = timezone.now()
            movement.save()

            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def reject_movement(request, movement_id):
    if request.method == 'POST':
        try:
            employee = Employee.objects.get(id=request.session['employee_id'])

            # Check if employee has reject permission
            if not can_approve_movements(employee):
                return JsonResponse({
                    'status': 'error',
                    'message': 'You do not have permission to reject movements'
                }, status=403)

            # Get the movement
            movement = AssetMovement.objects.get(id=movement_id)

            # Check if the approver is the same person who initiated the request
            if movement.initiator == employee:
                return JsonResponse({
                    'status': 'error',
                    'message': 'You cannot reject movements you initiated'
                }, status=403)

            movement.status = 'REJECTED'
            movement.approver = employee
            movement.approval_date = timezone.now()
            movement.save()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def movement_details(request, movement_id):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    movement = get_object_or_404(AssetMovement, id=movement_id)

    return render(request, 'myapp/movement_details.html', {
        'employee': employee,
        'movement': movement
    })


def it_management(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])
    # Get all non-deleted assets with related departments
    assets = Asset.objects.select_related('department').filter(
        is_deleted=False
    ).order_by('-created_at')

    context = {
        'employee': employee,
        'departments': Department.objects.filter(is_active=True),
        'assets': assets,
        'stats': {
            'total_count': assets.count(),
            'active_count': assets.filter(is_active=True).count(),
            'maintenance_count': assets.filter(condition='POOR').count(),
            'retired_count': assets.filter(condition='RETIRED').count(),
        }
    }
    return render(request, 'myapp/it_management.html', context)


def movement_approvals(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])

    # Check if employee has approve permission
    can_approve = can_approve_movements(employee)
    if not can_approve:
        messages.error(
            request, 'You do not have permission to access this page')
        return redirect('dashboard')

    # Get pending movements that need approval
    pending_movements = AssetMovement.objects.filter(
        status='PENDING'
    ).select_related(
        'asset', 'initiator'
    ).order_by('-created_at')

    context = {
        'employee': employee,
        'pending_movements': pending_movements,
        'approval_stats': {
            'pending_count': pending_movements.count(),
            'approved_count': AssetMovement.objects.filter(status='APPROVED').count(),
            'rejected_count': AssetMovement.objects.filter(status='REJECTED').count(),
        }
    }
    return render(request, 'myapp/movement_approvals.html', context)


def role_management(request):
    roles = Role.objects.all()
    available_permissions = {
        'Employee': ['view', 'add', 'edit', 'delete'],
        'Department': ['view', 'add', 'edit', 'delete'],
        'Asset': ['view', 'add', 'edit', 'delete'],
        'Report': ['view', 'generate'],
        # Added approve permission
        'Movement': ['view', 'create', 'edit', 'approve', 'reject']
    }

    context = {
        'roles': roles,
        'available_permissions': available_permissions,
        # Fix the employee context
        'employee': Employee.objects.get(id=request.session['employee_id']),
        'all_employees': Employee.objects.filter(is_active=True).order_by('surname', 'name')
    }
    return render(request, 'myapp/role_management.html', context)


def add_role(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        permissions = request.POST.getlist('permissions')

        # Convert permissions list to structured dict
        permission_dict = {}
        for perm in permissions:
            module, action = perm.split('_')
            if module not in permission_dict:
                permission_dict[module] = []
            permission_dict[module].append(action)

        Role.objects.create(
            name=name,
            description=description,
            permissions=permission_dict
        )

        return redirect('role_management')
    return redirect('role_management')


def toggle_role_status(request, role_id):
    if request.method == 'POST':
        role = Role.objects.get(id=role_id)
        role.is_active = not role.is_active
        role.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


def get_role_users(request, role_id):
    """Get all employees assigned to a specific role"""
    if 'employee_id' not in request.session:
        return JsonResponse({'status': 'error', 'message': 'Not authenticated'}, status=401)

    try:
        role = Role.objects.get(id=role_id)
        employees = role.employee_set.values_list('id', flat=True)
        return JsonResponse({
            'status': 'success',
            'employees': list(employees)
        })
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


def assign_users_to_role(request):
    """Assign multiple users to a role"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    if 'employee_id' not in request.session:
        return JsonResponse({'status': 'error', 'message': 'Not authenticated'}, status=401)

    try:
        role_id = request.POST.get('role_id')
        role = Role.objects.get(id=role_id)

        # Get the selected employee IDs
        employee_ids = request.POST.getlist('employee_ids')

        # Clear existing role assignments for this role
        role.employee_set.clear()

        # Assign the role to selected employees
        if employee_ids:
            employees = Employee.objects.filter(id__in=employee_ids)
            for employee in employees:
                employee.roles.add(role)

        messages.success(
            request, f'Users successfully assigned to role "{role.name}"')
        return redirect('role_management')
    except Exception as e:
        messages.error(request, f'Error assigning users: {str(e)}')
        return redirect('role_management')


def edit_role(request, role_id):
    """Edit an existing role"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

    if 'employee_id' not in request.session:
        return redirect('login')

    try:
        role = Role.objects.get(id=role_id)
        role.name = request.POST.get('name')
        role.description = request.POST.get('description')

        # Update permissions
        permissions = request.POST.getlist('permissions')
        permission_dict = {}
        for perm in permissions:
            module, action = perm.split('_')
            if module not in permission_dict:
                permission_dict[module] = []
            permission_dict[module].append(action)

        role.permissions = permission_dict
        role.save()

        messages.success(request, f'Role "{role.name}" updated successfully')
        return redirect('role_management')
    except Exception as e:
        messages.error(request, f'Error updating role: {str(e)}')
        return redirect('role_management')


def get_role_data(request, role_id):
    """Get role data for editing"""
    if 'employee_id' not in request.session:
        return JsonResponse({'status': 'error', 'message': 'Not authenticated'}, status=401)

    try:
        role = Role.objects.get(id=role_id)

        # Format permissions for frontend
        formatted_permissions = []
        for module, actions in role.permissions.items():
            for action in actions:
                formatted_permissions.append(f"{module}_{action}")

        return JsonResponse({
            'status': 'success',
            'role': {
                'id': role.id,
                'name': role.name,
                'description': role.description,

                'permissions': formatted_permissions
            }
        })
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


def movement_history(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])

    # Get all movements with approval info
    movements = AssetMovement.objects.select_related(
        'asset', 'initiator', 'approver'
    ).order_by('-created_at')

    # Filter by status if provided
    status_filter = request.GET.get('status')
    if status_filter and status_filter.upper() in ['PENDING', 'APPROVED', 'REJECTED']:
        movements = movements.filter(status=status_filter.upper())

    return render(request, 'myapp/movement_history.html', {
        'employee': employee,
        'movements': movements,
        'stats': {
            'total': AssetMovement.objects.count(),
            'pending': AssetMovement.objects.filter(status='PENDING').count(),
            'approved': AssetMovement.objects.filter(status='APPROVED').count(),
            'rejected': AssetMovement.objects.filter(status='REJECTED').count(),
        }
    })


def schedule_maintenance(request):
    if request.method == 'POST':
        try:
            # Check if user is authenticated
            if 'employee_id' not in request.session:
                return JsonResponse({
                    'status': 'error',
                    'message': 'User not authenticated'
                }, status=401)

            employee = Employee.objects.get(id=request.session['employee_id'])

            # Get and validate required fields
            asset_id = request.POST.get('asset_id')
            if not asset_id:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Asset ID is required'
                }, status=400)

            scheduled_date_str = request.POST.get('scheduled_date')
            if not scheduled_date_str:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Scheduled date is required'
                }, status=400)

            try:
                scheduled_date = datetime.strptime(
                    scheduled_date_str, '%Y-%m-%d').date()
            except ValueError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid date format. Please use YYYY-MM-DD format.'
                }, status=400)

            description = request.POST.get('description')
            if not description:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Description is required'
                }, status=400)

            maintenance_type = request.POST.get('maintenance_type')
            if not maintenance_type:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Maintenance type is required'
                }, status=400)

            technician = request.POST.get('technician')
            if not technician:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Technician is required'
                }, status=400)

            # Get optional fields
            estimated_cost = request.POST.get('estimated_cost')
            if estimated_cost:
                try:
                    estimated_cost = float(estimated_cost)
                except ValueError:
                    return JsonResponse({
                        'status': 'error',
                        'message': 'Invalid estimated cost format'
                    }, status=400)

            # Create the maintenance record
            maintenance = AssetMaintenance.objects.create(
                asset_id=asset_id,
                scheduled_date=scheduled_date,
                description=description,
                maintenance_type=maintenance_type,
                estimated_cost=estimated_cost,
                technician=technician,
                created_by=employee
            )

            return JsonResponse({
                'status': 'success',
                'message': 'Maintenance scheduled successfully',
                'maintenance': {
                    'id': maintenance.id,
                    'scheduled_date': maintenance.scheduled_date.strftime('%Y-%m-%d'),
                    'status': maintenance.get_status_display()
                }
            })
        except Employee.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Employee not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error scheduling maintenance: {str(e)}'
            }, status=400)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


def update_maintenance_status(request, maintenance_id):
    if request.method == 'POST':
        try:
            maintenance = AssetMaintenance.objects.get(id=maintenance_id)
            new_status = request.POST.get('status')

            if new_status not in dict(AssetMaintenance.MAINTENANCE_STATUS):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid maintenance status'
                }, status=400)

            maintenance.status = new_status
            if new_status == 'COMPLETED':
                maintenance.completion_date = timezone.now().date()
                maintenance.completion_notes = request.POST.get(
                    'completion_notes', '')
            maintenance.save()

            return JsonResponse({
                'status': 'success',
                'message': 'Maintenance status updated successfully'
            })
        except AssetMaintenance.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Maintenance schedule not found'
            }, status=404)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Error updating maintenance status: {str(e)}'
            }, status=400)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


def get_asset_maintenance_history(request, asset_id):
    try:
        if asset_id == 'all':
            # Get all maintenance records
            maintenance_records = AssetMaintenance.objects.select_related(
                'asset').all()
        else:
            # Get maintenance records for a specific asset
            maintenance_records = AssetMaintenance.objects.select_related(
                'asset').filter(asset_id=asset_id)

        records = [{
            'id': record.id,
            'asset_name': record.asset.name if record.asset else '-',
            'maintenance_type': record.maintenance_type,
            'scheduled_date': record.scheduled_date.strftime('%Y-%m-%d'),
            'technician': record.technician,
            'status': record.status,
            'estimated_cost': float(record.estimated_cost) if record.estimated_cost else None,
            'completion_date': record.completion_date.strftime('%Y-%m-%d') if record.completion_date else None,
            'completion_notes': record.completion_notes
        } for record in maintenance_records]

        return JsonResponse({
            'status': 'success',
            'maintenance_records': records
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)


def maintenance_records(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    employee = Employee.objects.get(id=request.session['employee_id'])

    # Get all maintenance records with related asset information
    maintenance_records = AssetMaintenance.objects.select_related(
        'asset').all().order_by('-scheduled_date')

    # Calculate statistics
    stats = {
        'total_records': maintenance_records.count(),
        'scheduled': maintenance_records.filter(status='SCHEDULED').count(),
        'in_progress': maintenance_records.filter(status='IN_PROGRESS').count(),
        'completed': maintenance_records.filter(status='COMPLETED').count(),
        'cancelled': maintenance_records.filter(status='CANCELLED').count()
    }

    # Get all active assets for the maintenance scheduling form
    active_assets = Asset.objects.filter(is_active=True)

    return render(request, 'myapp/maintenance_records.html', {
        'employee': employee,
        'maintenance_records': maintenance_records,
        'stats': stats,
        'assets': active_assets
    })


def export_asset_list(request):
    if 'employee_id' not in request.session:
        return redirect('login')

    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="asset_list_{timestamp}.csv"'

    # Create CSV writer
    writer = csv.writer(response)

    # Write header row
    writer.writerow([
        'Asset Number',
        'Serial Number',
        'Name',
        'Category',
        'Department',
        'Location',
        'Purchase Date',
        'Purchase Cost',
        'Condition',
        'Status',
        'Last Updated'
    ])

    # Get all non-deleted assets
    assets = Asset.objects.select_related(
        'department').filter(is_deleted=False)

    # Write data rows
    for asset in assets:
        writer.writerow([
            asset.asset_number,
            asset.serial_number or '',
            asset.name,
            asset.category,
            asset.department.name if asset.department else '',
            asset.location or '',
            asset.purchase_date,
            asset.purchase_cost,
            asset.condition,
            'Active' if asset.is_active else 'Inactive',
            asset.updated_at.strftime(
                '%Y-%m-%d %H:%M:%S') if asset.updated_at else ''
        ])

    return response


def get_asset_details(request, asset_id):
    if request.method == 'GET':
        try:
            asset = Asset.objects.select_related('department').get(id=asset_id)
            return JsonResponse({
                'status': 'success',
                'asset': {
                    'asset_number': asset.asset_number,
                    'serial_number': asset.serial_number or '',
                    'name': asset.name,
                    'category': asset.category,
                    'department': str(asset.department.id) if asset.department else '',
                    'condition': asset.condition,
                    'location': asset.location or '',
                    'purchase_date': asset.purchase_date.strftime('%Y-%m-%d') if asset.purchase_date else '',
                    'purchase_cost': str(asset.purchase_cost) if asset.purchase_cost else '',
                    'description': asset.description or ''
                }
            })
        except Asset.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Asset not found'}, status=404)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

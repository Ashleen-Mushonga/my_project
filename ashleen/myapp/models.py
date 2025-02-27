from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.hashers import make_password


class Department(models.Model):
    code = models.CharField(max_length=10, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    permissions = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Employee(models.Model):
    employee_number = models.CharField(max_length=10, unique=True)
    name = models.CharField(max_length=100)
    surname = models.CharField(max_length=100)
    department = models.ForeignKey(Department, on_delete=models.PROTECT)
    branch = models.CharField(max_length=100)
    section = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_regex = RegexValidator(
        regex=r'^07\d{8}$',
        message="Phone number must start with '07' and be 10 digits long"
    )
    phone_number = models.CharField(
        validators=[phone_regex],
        max_length=10,
        unique=True
    )
    signature = models.ImageField(
        upload_to='signatures/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    password = models.CharField(
        max_length=128, default=make_password('defaultpassword'))
    is_first_login = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    roles = models.ManyToManyField(Role, blank=True)

    def save(self, *args, **kwargs):
        if self._state.adding:  # Only when creating new employee
            # Create initial password as employee_number + surname in lowercase
            initial_password = f"{self.employee_number}{self.surname}".lower()
            self.password = make_password(initial_password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.employee_number} - {self.name} {self.surname}"

    class Meta:
        ordering = ['surname', 'name']


class Module(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    icon = models.CharField(
        max_length=50, help_text="Font Awesome icon class (e.g., 'fa-users')")
    url = models.CharField(max_length=200)
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


# You can add this using the admin interface or create a migration with this data:
"""
Module.objects.create(
    name='IT Management',
    description='Manage IT assets, requests, and support tickets',
    icon='fa-laptop',
    url='/it-management/',
    order=3  # Adjust based on your existing modules
)
"""


class Asset(models.Model):
    CONDITION_CHOICES = [
        ('NEW', 'New'),
        ('GOOD', 'Good'),
        ('FAIR', 'Fair'),
        ('POOR', 'Poor'),
        ('RETIRED', 'Retired'),
    ]

    asset_number = models.CharField(max_length=50, unique=True)
    serial_number = models.CharField(
        max_length=100, blank=True, null=True)  # Add this line
    name = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    department = models.ForeignKey(
        Department, on_delete=models.SET_NULL, null=True)
    location = models.CharField(max_length=100)
    purchase_date = models.DateField()
    purchase_cost = models.DecimalField(max_digits=10, decimal_places=2)
    condition = models.CharField(max_length=10, choices=CONDITION_CHOICES)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        Employee, on_delete=models.SET_NULL, null=True, blank=True, related_name='deleted_assets')
    initiator = models.ForeignKey(
        Employee, on_delete=models.SET_NULL, null=True, related_name='initiated_assets')

    def soft_delete(self, employee):
        from django.utils import timezone
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = employee
        self.is_active = False
        self.save()

    def __str__(self):
        return f"{self.asset_number} - {self.name}"


class AssetMovement(models.Model):
    MOVEMENT_TYPES = [
        ('TRANSFER', 'Transfer'),
        ('DISPOSAL', 'Disposal'),
        ('REPAIR', 'Repair'),
    ]

    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ]

    STAGE_CHOICES = [
        ('INITIATED', 'Initiated'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
    ]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    movement_type = models.CharField(max_length=20, choices=MOVEMENT_TYPES)
    from_location = models.CharField(max_length=100)
    to_location = models.CharField(max_length=100)
    reason = models.TextField()
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='PENDING')
    stage = models.CharField(
        max_length=20, choices=STAGE_CHOICES, default='INITIATED')
    initiator = models.ForeignKey(
        Employee, on_delete=models.CASCADE, related_name='initiated_movements')
    attachment = models.FileField(upload_to='movement_attachments/', null=True, blank=True,
                                  help_text="Upload any relevant documents (e.g., transfer forms, repair reports)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_movement_type_display()} - {self.asset.name}"

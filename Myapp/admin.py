from django.contrib import admin
from Myapp.models import Contact, MutualFund, ProfilePic  # ✅ Keep these

# Register Contact Model
admin.site.register(Contact)
admin.site.register(ProfilePic)

# Register MutualFund Model
@admin.register(MutualFund)
class MutualFundAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'risk', 'return_rate', 'duration', 'investment_type', 'profit_type')
    search_fields = ('name', 'category')

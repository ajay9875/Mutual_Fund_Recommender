from django.contrib import admin
from Myapp.models import Contact, MutualFund, ProfilePic, AllMutualFund  # ✅ Keep these

# Register Contact Model
admin.site.register(Contact)
admin.site.register(ProfilePic)

# Register MutualFund Model
@admin.register(MutualFund)
class MutualFundAdmin(admin.ModelAdmin):
    list_display = ('username', 'fund_name', 'investment_type', 'subcategory', 'nav', 'rating')
    search_fields = ('username', 'fund_name', 'investment_type', 'subcategory')  # only CharFields
    list_filter = ('rating', 'investment_type', 'subcategory')  # for easy filtering

# Register AllMutualFund Model
@admin.register(AllMutualFund)
class AllMutualFund(admin.ModelAdmin):
    list_display = ('fund_name',)  # ✅ Only include available fields
    search_fields = ('fund_name',)

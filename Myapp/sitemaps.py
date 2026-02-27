from django.contrib.sitemaps import Sitemap
from django.urls import reverse
from .models import AllMutualFund  # Use your AllMutualFund model

class FundSitemap(Sitemap):
    changefreq = "weekly"
    priority = 0.8

    def items(self):
        # This returns all the unique funds you've listed
        return AllMutualFund.objects.all()

    def location(self, obj):
        # Replace 'fund_detail' with the name of your URL route
        from django.urls import reverse
        return reverse('fund_details', kwargs={'fund_name': obj.fund_name})
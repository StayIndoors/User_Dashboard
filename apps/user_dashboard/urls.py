from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^signin$', views.signin),
    url(r'^register$', views.register),
    url(r'^process_signin$', views.process_signin),
    url(r'^process_register$', views.process_register),
    url(r'^dashboard/admin$', views.admin_dashboard),
    url(r'^dashboard$', views.user_dashboard),    
    url(r'^users/show/(?P<user_id>\d+)$', views.show_user),
    url(r'^logout$', views.logout),
    url(r'^users/new$', views.new_user),
    url(r'^users/add_new$', views.add_user),
]
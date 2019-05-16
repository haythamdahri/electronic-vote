from SecuredVote.forms import SearchForm

# Global variables
def global_var(request):
    context = dict()
    search_form = SearchForm()
    context['search_form'] = search_form
    return context
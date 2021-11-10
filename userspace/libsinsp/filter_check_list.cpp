/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <cstdint>

#include "sinsp.h"

#ifdef HAS_FILTERING
#include "filter_check_list.h"
#include "filterchecks.h"

using namespace std;



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// filter_check_list 
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// costruttore vuoto
filter_check_list::filter_check_list()
{
}

// viene richiamato anche quando il distruttore di sinsp_filter_check_list viene chiamato.
filter_check_list::~filter_check_list()
{
	for(auto *chk : m_check_list)
	{
		delete chk;
	}
}

// questi filter_check sono oggetti della classe sinsp_filter_check
// si fa il giochetto dell'ereditarietà in realtà i filter check ereditano tutti dalla classe sinsp_filter_check 
void filter_check_list::add_filter_check(sinsp_filter_check* filter_check)
{
	// pusha solo nel vector gli oggetti filter checks
	m_check_list.push_back(filter_check);
}

void filter_check_list::get_all_fields(vector<const filter_check_info*>& list)
{
	for(auto *chk : m_check_list)
	{
		list.push_back((const filter_check_info*)&(chk->m_info));
	}
}

// nuovo filtercheck dal nome che gli arriva (evt.category)
// ritorna il filtercheck del tipo giusto se ovviamente è presente.
sinsp_filter_check* filter_check_list::new_filter_check_from_fldname(const string& name,
								     sinsp* inspector,
								     bool do_exact_check)
{
	// per tutti i sinsp_filter_check presenti setto l'inspector
	// nota che questi filter_check nel vector discendono da sinsp_filter_check quindi per esempio sono sinsp_filter_check_fd, ...
	for(auto *chk : m_check_list)
	{
		chk->m_inspector = inspector;

		// questa funzione parse_filed_name è una funzione che ereditano tutti i filter checks
		// quindi chiamo quella specifica del filter_check che sto usando!!!
		int32_t fldnamelen = chk->parse_field_name(name.c_str(), false, true);

		// se ho trovato una corrispondenza in questo filter_check significa che era quello giusto
		if(fldnamelen != -1)
		{
			// nel caso visto lo passo uguale a true
			if(do_exact_check)
			{
				// si controlla che effetivamente il filed sia realmente uguale.
				if((int32_t)name.size() != fldnamelen)
				{
					goto field_not_found;
				}
			}

			// alloco un filter_check di quel tipo
			// ho capito quale è il filtercheck giusto
			sinsp_filter_check* newchk = chk->allocate_new();
			newchk->set_inspector(inspector);
			return newchk;
		}
	}

field_not_found:

	//
	// If you are implementing a new filter check and this point is reached,
	// it's very likely that you've forgotten to add your filter to the list in
	// the constructor
	//
	return NULL;
}

sinsp_filter_check* filter_check_list::new_filter_check_from_another(sinsp_filter_check *chk)
{
	sinsp_filter_check *newchk = chk->allocate_new();

	newchk->m_inspector = chk->m_inspector;
	newchk->m_field_id = chk->m_field_id;
	newchk->m_field = &chk->m_info.m_fields[chk->m_field_id];

	newchk->m_boolop = chk->m_boolop;
	newchk->m_cmpop = chk->m_cmpop;

	return newchk;
}
















///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_list 
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// come costruttore base aggiunge una serie di filter_check
sinsp_filter_check_list::sinsp_filter_check_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_filter_check(new sinsp_filter_check_fd());
	add_filter_check(new sinsp_filter_check_thread());
	add_filter_check(new sinsp_filter_check_gen_event());
	add_filter_check(new sinsp_filter_check_event());
	add_filter_check(new sinsp_filter_check_user());
	add_filter_check(new sinsp_filter_check_group());
	add_filter_check(new sinsp_filter_check_syslog());
	add_filter_check(new sinsp_filter_check_container());
	add_filter_check(new sinsp_filter_check_utils());
	add_filter_check(new sinsp_filter_check_fdlist());
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	add_filter_check(new sinsp_filter_check_k8s());
	add_filter_check(new sinsp_filter_check_mesos());
#endif // !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	add_filter_check(new sinsp_filter_check_tracer());
	add_filter_check(new sinsp_filter_check_evtin());
}

sinsp_filter_check_list::~sinsp_filter_check_list()
{
}

#endif // HAS_FILTERING

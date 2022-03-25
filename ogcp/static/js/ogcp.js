const Endpoint = '/scopes/status';
const Interval = 1000;
let updateTimeoutId = null;

function showSelectedClient(client_checkbox) {
    const container = $('#selected-clients');
    const pill_id = 'pill-' + client_checkbox.name.replaceAll(/[.]|[ ]/g, '_');

    if (client_checkbox.checked) {
        if (!($('#' + pill_id).length))
            $(container).append('<div class="badge badge-pill og-pill badge-light" ' +
                                'id="'+ pill_id + '">' + client_checkbox.name +
                                '<br>' + client_checkbox.value + '</div>');
        return;
    }

    $('#' + pill_id, container).remove();
}

function showSelectedClientsOnEvents() {
    const checkboxes = $('input:checkbox[form|="scopesForm"]');
    const container = $('#selected-clients');

    const client_checkboxes = checkboxes.filter(function () {
        return $(this).siblings().length == "1";
    });

    client_checkboxes.on('change show-client', function () {
        showSelectedClient(this);
    });
}

function storeCheckboxStatus(checkbox) {
        if (checkbox.checked)
            localStorage.setItem(checkbox.name, "check");
        else
            localStorage.removeItem(checkbox.name);
}

function checkChildrenCheckboxes() {
    const checkboxes = $('input:checkbox[form|="scopesForm"]')

    checkboxes.on('change', function () {
        const checked = this.checked
        const children = $('input:checkbox', this.parentNode).not(this)
        children.each(function () {
            this.checked = checked;
            storeCheckboxStatus(this);
            $(this).trigger('show-client');
        });
    });
}

function keepSelectedClients() {
    const checkboxes = $('input:checkbox[form|="scopesForm"]')

    checkboxes.on('change', function (event) {
            storeCheckboxStatus(this);
    });

    checkboxes.each(function () {
        if (localStorage.getItem(this.name) == 'check') {
            this.checked = true;
            $(this).trigger('show-client');
        }
    });
}

function keepScopesTreeState() {
    const scopes_tree = $('#scopes .collapse')

    scopes_tree.on('hidden.bs.collapse', function (event) {
        event.stopPropagation();
        localStorage.removeItem(this.id);
    });
    scopes_tree.on('shown.bs.collapse', function (event) {
        event.stopPropagation();
        localStorage.setItem(this.id, 'show');
    });

    scopes_tree.each(function () {
        if (localStorage.getItem(this.id) == 'show') {
            $(this).collapse('show');
        }
    });
}

function updateScopeState() {
    if (updateTimeoutId) {
        clearTimeout(updateTimeoutId);
    }

    updateTimeoutId = setTimeout(() => {
        updateTimeoutId = null;
        fetch(Endpoint)
            .then(response => response.json())
            .then((data) => {
                updateScopes(data.scope);
            })
            .catch((error) => { console.error(error); })
            .finally(() => {
                updateScopeState();
            });
    }, Interval);
}

function updatePillStatus(state, pill) {
    const pillCls = ['badge-danger', 'badge-success', 'badge-warning',
                     'badge-wol', 'badge-light'];
    pill.classList.remove(...pillCls);
    if (state === 'OPG') {
        pill.classList.add('badge-warning');
    } else if (state === 'BSY') {
        pill.classList.add('badge-danger');
    } else if (state === 'VDI') {
        pill.classList.add('badge-success');
    } else if (state === 'WOL_SENT') {
        pill.classList.add('badge-wol');
    } else {
        pill.classList.add('badge-light');
    }
}

function updateScopes(scopes) {
    scopes.forEach((scope) => {
        if (scope.state) {
            const scopeId = `${scope.name}_${scope.id}`.replaceAll(/[.]|[ ]/g, '_');
            const iconEl = document.querySelector(`#${scopeId} .nav-icon`);
            const iconCls = ['fas', 'far', 'text-danger', 'text-success',
                             'text-warning', 'text-wol'];
            iconEl.classList.remove(...iconCls);
            let newIconCls = [];
            if (scope.state === 'OPG') {
                newIconCls.push('fas', 'text-warning');
            } else if (scope.state === 'BSY') {
                newIconCls.push('fas', 'text-danger');
            } else if (scope.state === 'VDI') {
                newIconCls.push('fas', 'text-success');
            } else if (scope.state === 'WOL_SENT') {
                newIconCls.push('fas', 'text-wol');
            } else {
                newIconCls.push('far');
            }
            iconEl.classList.add(...newIconCls);

            const pillScopeId = `pill-${scopeId}`;
            const pillEl = document.querySelector(`#${pillScopeId}`);
            if (pillEl)
                updatePillStatus(scope.state, pillEl);
        }
        if (scope.scope) {
            // This is a level so we should update all childs
            updateScopes(scope.scope);
        }
    });
}

function unfoldAll() {
    $('#scopes .collapse').collapse('show');
}

function AddPartition(evt) {
    const target = $($(evt).data("target"));
    const oldrow = target.find("[data-toggle=fieldset-entry]:last");
    const row = oldrow.clone(true, true);
    const elem_id = row.find(".form-control")[0].id;
    const elem_num = parseInt(elem_id.replace(/(.*)-(\d{1,4})/m, '$2')) + 1;
    // Increment WTForms unique identifiers
    row.find('.form-control').each(function() {
        const id = $(this).attr('id').replace(/(.*)-(\d{1,4})-(.*)/, `$1-${elem_num}-$3`);
        $(this).attr('name', id).attr('id', id).val('').removeAttr("checked");
    });
    row.show();
    oldrow.after(row);
}

function RemovePartition(evt) {
    const target = $(evt).parent().parent();
    const table = target.parent();
    target.remove();

    // Reassign rows ids
    table.find('tr').each(function(index) {
        $(this).find('.form-control').each(function() {
            const id = $(this).attr('id').replace(/(.*)-(\d{1,4})-(.*)/, `$1-${index}-$3`);
            $(this).attr('name', id).attr('id', id);
        });
    });
}

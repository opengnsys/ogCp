const Endpoint = '/scopes/status';
const Interval = 1000;
let updateTimeoutId = null;

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

function updateScopes(scopes) {
    scopes.forEach((scope) => {
        if (scope.state) {
            const scopeId = `${scope.name}_${scope.id}`;
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
    const elem_id = row.find(":input")[0].id;
    const elem_prefix = elem_id.replace(/(.*)-(\d{1,4})/m, '$1')// max 4 digits for ids in list
    const elem_num = parseInt(elem_id.replace(/(.*)-(\d{1,4})/m, '$2')) + 1;
    // Increment WTForms unique identifiers
    row.children(':input').each(function() {
        const id = $(this).attr('id').replace(elem_prefix+'-' + (elem_num - 1),
                                              elem_prefix+'-' + (elem_num));
        $(this).attr('name', id).attr('id', id).val('').removeAttr("checked");
    });
    row.show();
    oldrow.after(row);
}

function RemovePartition(evt) {
    const target = $(evt).parent().parent();
    target.remove();
}

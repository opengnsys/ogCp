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

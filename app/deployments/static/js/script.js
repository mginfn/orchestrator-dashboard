function showIfNotZero(el) {
    let fname = showIfNotZero.name.toLowerCase();
    let selector = $(el).data(`${fname}-id-filter`);
    let id_pattern = new RegExp(selector);

    let search_id = $('[id]').filter(function () {
        return id_pattern.test(this.id);
    });
    let value = el.value.trim(); // Trim to handle potential whitespace

    search_id.each(function () {
        if (this.id !== el.id) {
            let parentFormGroup = $(this).closest('div.form-group');
            let shouldShow = value !== '0';

            parentFormGroup.attr('hidden', !shouldShow);

            let dataRequired = $(el).attr('data-required');

            if(shouldShow && dataRequired !== undefined && dataRequired.toLowerCase() === 'true'){
                $(el).prop('required', true);    
            } else {
                $(el).prop('required', false);
            }
        }
    });
}


function showElems(el) {
    let fname = showElems.name.toLowerCase();
    let selector = $(el).data(`${fname}-id-filter`);
    let id_pattern = new RegExp(selector);

    let search_id = $('[id]').filter(function () {
        return id_pattern.test(this.id);
    });

    let pattern = $(el).data(`${fname}-${el.value.toString()}-pattern`);
    let re = new RegExp(pattern);

    search_id.each(function () {
        if (this.id !== el.id) {
            let parentFormGroup = $(this).closest('div.form-group');

            parentFormGroup.attr('hidden', true);
            $(this).prop('required', false);
            console.log(this);


            if (pattern && re.test(this.id)) {
                parentFormGroup.attr('hidden', false);
                // restore required property according to the original value
                let dataRequired = $(this).attr('data-required');
                if (dataRequired !== undefined && dataRequired.toLowerCase() === 'true'){
                    $(this).prop('required', true);    
                }
            
            }
        }
    });
}
import click
import os
import io
import yaml
import pyrx
import jsonschema
import re

from .modules.mitre import mitre_pull
from .schema import rx_schema, json_schema, s2_schema

rx = pyrx.Factory({'register_core_types': True})

schema = rx.make_schema(rx_schema)

@click.command()
@click.option('--sigmainput', type=click.Path(exists=True, file_okay=True, readable=True, resolve_path=True), help='Path to a directory that comtains Sigma files or to a single Sigma file.', required=True)
@click.option('--directory', is_flag=True, help="Flag for if sigmainput is a directory")
@click.option('--method', type=click.Choice(['rx', 'jsonschema', 's2'], case_sensitive=False), default='rx', help='Validation method.')
@click.option('--mitre', is_flag=True, help='Enrich Sigma file with MITRE content based off of any MITRE references in tags.  This will append to the Sigma file.', required=False)
def cli(sigmainput, directory, method, mitre):
    results = []
    filepaths = []
    
    if(directory):
        print("Directory True")
        filepaths = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(sigmainput)) for f in fn]
    else:
        seperator = '\\'
        filepaths=[sigmainput]
        pathParts = sigmainput.split(seperator)
        a_filename = pathParts[-1]
        pathParts.pop()
        sigmainput = seperator.join(pathParts)

    invalid_count = 0
    unsupported_count = 0

    with click.progressbar(filepaths, label="Parsing yaml files:") as bar:
        for filename in bar:
            if filename.endswith('.yml'):
                f = open(os.path.join(sigmainput, filename), 'r')
                sigma_yaml = yaml.safe_load_all(f)
                sigma_yaml_list = list(sigma_yaml)
                if len(sigma_yaml_list) > 1:
                    results.append({'result': True, 'reasons': ['Multi-document YAML files are not supported currently'], 'filename': filename})
                    unsupported_count = unsupported_count + 1
                else:
                    if method == 'rx':
                        result = schema.check(sigma_yaml_list[0])
                        reason = 'valid' if result else 'invalid'
                        results.append({'result': result, 'reasons': [reason], 'filename': filename})
                    elif method == 'jsonschema' or method == 's2':
                        method_schema = json_schema if method == 'jsonschema' else s2_schema
                        v = jsonschema.Draft7Validator(method_schema)
                        errors = []
                        for error in sorted(v.iter_errors(sigma_yaml_list[0]), key=str):    
                            errors.append(error.message)
                        result = False if len(errors) > 0 else True
                        results.append({'result': result, 'reasons': errors, 'filename': filename})

                    if mitre:
                        ## Most mentions of MITRE are currently found in the 'tags' field for Sigma rules
                        if 'tags' in sigma_yaml_list[0]:
                            for tag in sigma_yaml_list[0]['tags']: 
                                if len(re.findall(r'(?i)t\d{4}',tag)) > 0:
                                    mitre_id = re.findall(r'(?i)t\d{4}',tag)
                                    mitre_id = mitre_id[0].upper()
                                    tactics, sub_techniques, technique_id, references = mitre_pull(mitre_id) 
                                    ## Prevent multiple writes to file if `mitre` key already exists
                                    if 'mitre' not in sigma_yaml_list[0]:
                                        sigma_yaml_list[0]['mitre'] = {} 
                                        sigma_yaml_list[0]['mitre']['tactics'] = [] 
                                        sigma_yaml_list[0]['mitre']['subTechniques'] = []
                                        sigma_yaml_list[0]['mitre']['techniqueIds'] = []
                                        sigma_yaml_list[0]['mitre']['references'] = []
                                    if tactics is not None and sub_techniques is not None and technique_id is not None and references is not None: 
                                        for tactic in tactics:
                                            ## Make sure we aren't duplicating
                                            if tactic not in sigma_yaml_list[0]['mitre']['tactics']:
                                                sigma_yaml_list[0]['mitre']['tactics'].append(tactic) 
                                            if sub_techniques not in sigma_yaml_list[0]['mitre']['subTechniques']:
                                                sigma_yaml_list[0]['mitre']['subTechniques'].append(sub_techniques)
                                            if technique_id not in sigma_yaml_list[0]['mitre']['techniqueIds']:
                                                sigma_yaml_list[0]['mitre']['techniqueIds'].append(technique_id)
                                            if references not in sigma_yaml_list[0]['mitre']['references']:
                                                sigma_yaml_list[0]['mitre']['references'].append(references)
                            with open(os.path.join(sigmainput, filename), 'w') as f:
                              yaml.dump(sigma_yaml_list[0], f)

    click.echo('Results:')

    for result in results:
        color = 'green' if result['result'] else 'red'
        if result['reasons']:
            if 'Multi-document' in result['reasons'][0]:
                color = 'yellow'
        if result['result'] == False:
            invalid_count = invalid_count + 1
            click.echo('========')
            click.secho('{} is invalid:'.format(os.path.join(sigmainput, result['filename'])), fg=color)
            for reason in result['reasons']:
                click.secho('\t * ' + reason, fg=color)

    click.echo('Total Valid Rule Files: {}'.format(str(len(results) - invalid_count) + "/" + str(len(results))))
    click.echo('Total Invalid Rule Files: {}'.format(str(invalid_count) + "/" + str(len(results))))
    click.echo('Total Unsupported Rule Files (Multi-document): {}'.format(str(unsupported_count) + "/" + str(len(results))))

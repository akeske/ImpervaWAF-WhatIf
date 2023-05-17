import { Component, OnInit } from '@angular/core';
import {
  SecurityRule,
  IPReputationRiskLevelEnum,
  MaliciousIPListEnum,
  ClientTypeEnum,
  VariableEnums,
  RuleSet,
  RuleExpression,
} from './model';
import { parseScript } from 'esprima';
import { FormGroup, FormControl, Validators } from '@angular/forms';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  ruleStrings: string[] = [
    'ClientType == HackingTool & (ASN != 29241 & ASN != 8075 & ASN != 56910)',
    'ClientType == HackingTool & (ASN != 29241;8075;56910)',
    'MaliciousIPList == TorIPs;AnonymousProxyIPs',
    'ClientType == Unknown & (ASN != 29241 & ASN != 8075 & ASN != 56910) & ClientIP != 83.212.175.132',
    'IPReputationRiskLevel == High',
    'IPReputationRiskLevel == Medium & CountryCode != GR',
    'ClientType == DDoSBot;Worm;MaskingProxy;ClickBot;CommentSpamBot;SpamBot;VulnerabilityScanner & ClientId != 453',
    '(URL not-contains "oauth";"saml") & (URL not-contains "/dashboard" | ( ClientIP != 62.103.236.223 & ClientIP != 20.50.146.69 & ClientIP != 20.73.36.250 & ClientIP != 62.169.201.60 & ClientIP != 62.103.236.223 & ClientIP != 62.169.197.77))',
  ];
  fakeUser: SecurityRule = {};
  ruless: RuleSet[] = [];

  fakeUserForm = new FormGroup({
    ClientType: new FormControl(localStorage.getItem('ClientType'), Validators.required),
    IPReputationRiskLevel: new FormControl(localStorage.getItem('IPReputationRiskLevel')),
    ASN: new FormControl(localStorage.getItem('ASN')),
    CountryCode: new FormControl(localStorage.getItem('CountryCode')),
    ClientIP: new FormControl(localStorage.getItem('ClientIP'), [
      Validators.required,
      Validators.pattern(
        '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
      ),
    ]),
    ClientId: new FormControl(localStorage.getItem('ClientId'), [
      Validators.required,
      Validators.min(1),
      Validators.max(985),
    ]),
    URL: new FormControl(localStorage.getItem('URL')),
    MaliciousIPList: new FormControl(localStorage.getItem('MaliciousIPList')),
  });

  constructor() {}

  onSubmit(form: FormGroup) {
    this.fakeUser = {
      ClientType: form.value.ClientType,
      IPReputationRiskLevel: form.value.IPReputationRiskLevel,
      ASN: form.value.ASN,
      CountryCode: form.value.CountryCode,
      ClientIP: form.value.ClientIP,
      ClientId: form.value.ClientId,
      URL: form.value.URL,
      MaliciousIPList: form.value.MaliciousIPList,
    };
    localStorage.setItem('ClientType', form.value.ClientType);
    localStorage.setItem('IPReputationRiskLevel', form.value.IPReputationRiskLevel);
    localStorage.setItem('ASN', form.value.ASN);
    localStorage.setItem('CountryCode', form.value.CountryCode);
    localStorage.setItem('ClientIP', form.value.ClientIP);
    localStorage.setItem('ClientId', form.value.ClientId);
    localStorage.setItem('URL', form.value.URL);
    localStorage.setItem('MaliciousIPList', form.value.MaliciousIPList);
    this.ruless = [];
    this.parseRules();
  }

  protected evaluate = (node: any): boolean => {
    if (node.type === 'LogicalExpression' || node.type === 'BinaryExpression') {
      const left = this.evaluate(node.left);
      const right = this.evaluate(node.right);
      switch (node.operator) {
        case '&':
          return left && right;
        case '|':
          return left || right;
        default:
          throw new Error(`Unknown operator: ${node.operator}`);
      }
    } else if (node.type === 'UnaryExpression') {
      return !node.argument;
    } else if (node.type === 'ExpressionStatement') {
      return this.evaluate(node.expression);
    } else if (node.type === 'Literal') {
      return node.value;
    } else if (node.type === 'Identifier') {
      // Assume that the identifier refers to a boolean value in the environment.
      return node.value;
    } else {
      throw new Error(`Unknown node type: ${node.type}`);
    }
  };

  protected parseRules(): void {
    const separators = ['&', '\\|', '\\(', '\\)'];
    let res = '';
    // get the rules
    this.ruleStrings.forEach(ruleString => {
      // create a new RuleSet object to store the rule string, results and expressions
      let ruleSet: RuleSet = new RuleSet();

      // set the rule from ruleString 
      ruleSet.rule = ruleString.replace(/;/g, ' ; ');
      
      // split the rulestring depends on '&,|,(,)' chars
      let ruleExpression = ruleString.split(
        new RegExp(separators.join('|'), 'g')
      );

      // get one-by-one the rule expressions 'type == value'
      let operator = '';
      let parenthesis = '';
      ruleExpression.forEach(rule => {
        rule = rule.trim();
        let type = '';
        let vars: string[] = [];
        // console.error(rule);
        let ruleTokens = rule.split(new RegExp(' ', 'g'));
        ruleTokens.forEach(ruleToken => {
          // console.error(ruleToken);
          let isVariable = false;
          let isSpecialChar = false;
          VariableEnums.forEach(variableEnum => {
            if (ruleToken.toLowerCase() === variableEnum.toLowerCase()) {
              type = ruleToken;
              isVariable = true;
            }
          });
          if (ruleToken.trim() == '==' || ruleToken.trim() == '!=') {
            isSpecialChar = true;
            operator = ruleToken.trim();
          }
          if (
            ruleToken.trim() == 'contains' ||
            ruleToken.trim() == 'not-contains'
          ) {
            isSpecialChar = true;
            operator = ruleToken.trim();
          }
          if (ruleToken.trim() == '(' || ruleToken.trim() == ')') {
            isSpecialChar = true;
            parenthesis = ruleToken.trim();
          }
          if (!isVariable && !isSpecialChar) {
            vars = ruleToken.split(new RegExp(';', 'g'));
          }
        });

        // for array of values, for example 'type == val1;val2;val3'
        let orOperator: any[] = [];
        Object.keys(this.fakeUser).forEach(key => {
          if (type === key) {
            vars.forEach(vari => {
              if (key === type) {
                // console.error(key + ' 1 ' + type);
                // console.error('  ' + type + '-' + operator + ' ' + vari);
                let bool: boolean;
                switch (operator) {
                  case '==':
                    // @ts-expect-error
                    bool = this.fakeUser[key] == vari;
                    break;
                  case '!=':
                    // @ts-expect-error
                    bool = this.fakeUser[key] != vari;
                    break;
                  case 'contains':
                    // @ts-expect-error
                    bool = vari.includes(this.fakeUser[key]);
                    break;
                  case 'not-contains':
                    // @ts-expect-error
                    bool = !vari.includes(this.fakeUser[key]);
                    break;
                  default:
                    bool = false;
                    break;
                }
                // the ruleExpression and its result (true or false)
                let ruleExpression: RuleExpression = {
                  ruleExpression: type + ' ' + operator + ' ' + vari,
                  result: bool,
                };
                ruleSet.ruleExpressions.push(ruleExpression);
                orOperator.push(bool);
              }
            });
          }
        });
        // if we have array of values then traspile it to or independent expressions
        operator = orOperator.join(' | ');

        // add parenthesis as the ruleString said
        if (parenthesis === '(') {
          ruleString += ' ( ';
        } else if (parenthesis === ')') {
          ruleString += ' ) ';
        }
        ruleString = ruleString.replace(rule, operator);
      });
      res = ruleString;
      ruleSet.boolExpression = res;

      let ast = parseScript(res);
      let result = this.evaluate(ast.body[0]);
      //  the result of rule stored on ruleSet, ready to present it on html
      ruleSet.result = result;
      // add to array of rules
      this.ruless.push(ruleSet);
    });
  }

  ipReputationRiskLevels: IPReputationRiskLevelEnum[] = [
    IPReputationRiskLevelEnum.Low,
    IPReputationRiskLevelEnum.Medium,
    IPReputationRiskLevelEnum.High,
  ];

  clientTypes: ClientTypeEnum[] = [
    ClientTypeEnum.DDoSBot,
    ClientTypeEnum.Worm,
    ClientTypeEnum.MaskingProxy,
    ClientTypeEnum.ClickBot,
    ClientTypeEnum.CommentSpamBot,
    ClientTypeEnum.SpamBot,
    ClientTypeEnum.VulnerabilityScanner,
    ClientTypeEnum.HackingTool,
    ClientTypeEnum.Unknown,
  ];

  MaliciousIPList: MaliciousIPListEnum[] = [
    MaliciousIPListEnum.AnonymousProxyIPs,
    MaliciousIPListEnum.TorIPs,
  ];
}
